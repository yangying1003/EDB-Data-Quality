import os
import re
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from openai import OpenAI


# =========================
# Basic Config
# =========================
INPUT_DIR = r"CVE01-25"
OUTPUT_DIR = r"CVE01-25_OUTPUT_platform"

MODEL_NAME = "qwen3.5-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# Request pacing
SLEEP_BETWEEN_REQUESTS = 0.5
MAX_RETRIES = 3
RETRY_DELAY = 2

# Whether to print raw model output
PRINT_RAW_RESPONSE = False

# =========================
# Resume Config
# =========================
# None means start from part_26
RESUME_FILE = "CVES_part_01.json"
# e.g. RESUME_FILE = "CVES_part_30.json"

# None means start from the first record in RESUME_FILE
RESUME_CVE_ID = None
# e.g. RESUME_CVE_ID = "CVE-2024-12345"

# Resume rules:
# 1. If RESUME_FILE = None, start from the first file in this batch.
# 2. If only RESUME_FILE is set, start from the first record of that file.
# 3. If both RESUME_FILE and RESUME_CVE_ID are set:
#    - if output already contains this CVE_ID, continue from the next record;
#    - otherwise start from this CVE_ID itself.


# =========================
# Init Client
# =========================
client = OpenAI(
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url=BASE_URL,
)

if not os.getenv("DASHSCOPE_API_KEY"):
    raise ValueError("DASHSCOPE_API_KEY environment variable is not set.")

# =========================
# Thinking / Token Monitor
# =========================
ENABLE_THINKING = False     # True = ask model to think first
THINKING_BUDGET = 50        # only used when ENABLE_THINKING = True

TOTAL_PROMPT_TOKENS = 0
TOTAL_COMPLETION_TOKENS = 0
TOTAL_TOKENS = 0

def get_usage_value(usage, key: str) -> int:
    if usage is None:
        return 0
    if isinstance(usage, dict):
        return int(usage.get(key, 0) or 0)
    return int(getattr(usage, key, 0) or 0)


def print_token_info(prompt_tokens: int, completion_tokens: int, total_tokens: int,
                     thinking_requested: bool, reasoning_detected: bool):
    print("\n" + "=" * 20 + " Token / Thinking Info " + "=" * 20)
    print(f"Thinking requested : {thinking_requested}")
    print(f"Reasoning detected : {reasoning_detected}")
    print(f"Prompt tokens      : {prompt_tokens}")
    print(f"Completion tokens  : {completion_tokens}")
    print(f"Total tokens       : {total_tokens}")
    print(f"Cumulative prompt  : {TOTAL_PROMPT_TOKENS}")
    print(f"Cumulative output  : {TOTAL_COMPLETION_TOKENS}")
    print(f"Cumulative total   : {TOTAL_TOKENS}")
    print("=" * 62 + "\n")
# =========================
# Prompt
# =========================
def build_prompt(description: str) -> str:
    return  f"""Task: Extract Platform label(s) from the following vulnerability description.
        Platform refers to the affected runtime environment, including:
        - Operating Systems
        - Hardware Architectures
        - Programming Languages or Frameworks

        You MUST choose labels ONLY from the following EDB Platform list:
        Operating Systems:
        AIX, Android, BeOS, BSD, FreeBSD, iOS, IRIX, Linux, macOS, MINIX, NetBSD,
        Netware, OpenBSD, Plan9, QNX, Solaris, SCO, Tru64, ULTRIX, UnixWare,
        VxWorks, Windows, watchOS, AtheOS, Immunix, Novell, HP-UX, Palm_OS
        Hardware:
        Alpha, ARM, CRISv32, MIPS, PPC, SPARC, x86, x86-64, SuperH_SH4, System_z
        Programming Languages:
        ASHX, ASP, ASPX, CGI, Go, Java, JSON, JSP, Lua, Perl, PHP, Python, Ruby, TypeScript, XML, CFM
        Other:
        eZine, Generator, Magazine
        Rules:
        - Extract only platforms affected by the vulnerability.
        - Distinguish between PoC implementation language and actual target platform.
        - Multiple labels are allowed.
        - Do NOT generate new labels.
        - Remove duplicates.
        - If no platform matches, return null (not an empty list).
        - Output strictly in the required format.
        Example Input:
        PoC: This vulnerability affects Linux servers running PHP applications.
        Chain-of-Thought:
        1. The affected operating system is Linux.
        2. The runtime language involved is PHP.
        3. Both belong to the Platform taxonomy.
        4. Therefore, extract Linux and PHP.
        Expected JSON format:
            {{ "extract_platform_CVE": ["Linux", "PHP"]}}
Vulnerability description:
{description}"""


# =========================
# Helpers
# =========================
def extract_json_text(text: str) -> str:
    text = text.strip()

    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)

    m = re.search(r"```\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)

    m = re.search(r"(\{.*\})", text, re.DOTALL)
    if m:
        return m.group(1)

    raise ValueError(f"JSON object not found in model output: {text}")


def ensure_str_list(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, list):
        return []

    cleaned = []
    seen = set()

    for item in value:
        if item is None:
            continue
        item = str(item).strip()
        if not item:
            continue
        if item not in seen:
            seen.add(item)
            cleaned.append(item)

    return cleaned


def normalize_result(data: Dict[str, Any]) -> Dict[str, List[str]]:
    return {
        "extract_platform_CVE": ensure_str_list(data.get("extract_platform_CVE"))
    }


def call_llm_extract(description: str) -> Dict[str, List[str]]:
    global TOTAL_PROMPT_TOKENS, TOTAL_COMPLETION_TOKENS, TOTAL_TOKENS

    prompt = build_prompt(description)
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            extra_body = {
                "enable_thinking": ENABLE_THINKING
            }
            if ENABLE_THINKING:
                extra_body["thinking_budget"] = THINKING_BUDGET

            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a vulnerability information extraction assistant. Output JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0,
                stream=True,
                stream_options={"include_usage": True},
                extra_body=extra_body
            )

            answer_content = ""
            reasoning_detected = False
            usage = None

            for chunk in completion:
                # 最后一段通常会携带 usage
                if getattr(chunk, "usage", None) is not None:
                    usage = chunk.usage

                if not getattr(chunk, "choices", None):
                    continue

                delta = chunk.choices[0].delta

                # 检测是否真的返回了 reasoning_content
                reasoning_content = getattr(delta, "reasoning_content", None)
                if reasoning_content:
                    reasoning_detected = True

                # 收集正式回答
                content = getattr(delta, "content", None)
                if content:
                    answer_content += content

            if PRINT_RAW_RESPONSE:
                print("\n=== Raw Model Output ===")
                print(answer_content)
                print("========================\n")

            prompt_tokens = get_usage_value(usage, "prompt_tokens")
            completion_tokens = get_usage_value(usage, "completion_tokens")
            total_tokens = get_usage_value(usage, "total_tokens")

            TOTAL_PROMPT_TOKENS += prompt_tokens
            TOTAL_COMPLETION_TOKENS += completion_tokens
            TOTAL_TOKENS += total_tokens

            print_token_info(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                thinking_requested=ENABLE_THINKING,
                reasoning_detected=reasoning_detected
            )

            json_text = extract_json_text(answer_content)
            data = json.loads(json_text)
            return normalize_result(data)

        except Exception as e:
            last_error = e
            print(f"  Attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    raise RuntimeError(f"Model call failed after retries: {last_error}")
def save_json(path: Path, data: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_json_if_exists(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Output file {path} is not a list.")
    return data


def find_index_by_cve_id(data: List[Dict[str, Any]], cve_id: str) -> int:
    for i, item in enumerate(data):
        item_cve_id = get_record_id(item)
        if item_cve_id == cve_id:
            return i
    return -1


def build_output_index_map(output_data: List[Dict[str, Any]]) -> Dict[str, int]:
    mapping = {}
    for i, item in enumerate(output_data):
        cve_id = get_record_id(item)
        if cve_id:
            mapping[cve_id] = i
    return mapping


# =========================
# Field Access
# =========================
def get_record_id(item: Dict[str, Any]) -> str:
    """
    Try several common key names for CVE record ID.
    Adjust here if your actual field name is different.
    """
    return (
        item.get("CVE_ID")
        or item.get("cve_id")
        or item.get("CVE")
        or item.get("id")
        or ""
    )


def get_description(item: Dict[str, Any]) -> str:
    """
    Try several common key names for description.
    Adjust here if your actual field name is different.
    """
    return (
        item.get("Description")
        or item.get("description")
        or item.get("vuln_descript")
        or item.get("desc")
        or ""
    )


# =========================
# Process One File
# =========================
def process_one_file(input_path: Path, output_path: Path, resume_cve_id: str = None):
    print(f"\nProcessing file: {input_path.name}")

    with input_path.open("r", encoding="utf-8") as f:
        input_data = json.load(f)

    if not isinstance(input_data, list):
        raise ValueError(f"{input_path.name} top-level structure is not a list.")

    output_data = load_json_if_exists(output_path)
    output_index_map = build_output_index_map(output_data)

    start_index = 0

    if resume_cve_id is not None:
        input_resume_index = find_index_by_cve_id(input_data, resume_cve_id)
        if input_resume_index == -1:
            raise ValueError(f"Resume CVE_ID not found in {input_path.name}: {resume_cve_id}")

        if resume_cve_id in output_index_map:
            start_index = input_resume_index + 1
            print(f"Resume CVE_ID {resume_cve_id} already exists in output. Continue from next record.")
        else:
            start_index = input_resume_index
            print(f"Resume CVE_ID {resume_cve_id} not found in output. Start from this record.")
    else:
        if output_data:
            processed_ids = set(output_index_map.keys())
            while start_index < len(input_data):
                cve_id = get_record_id(input_data[start_index])
                if cve_id in processed_ids:
                    start_index += 1
                else:
                    break
            if start_index > 0:
                print(f"Existing output detected. Resume from record {start_index + 1}.")

    total = len(input_data)

    for idx in range(start_index, total):
        item = input_data[idx]
        cve_id = get_record_id(item)
        description = get_description(item)

        print(f"[{idx + 1}/{total}] CVE_ID = {cve_id}")

        if cve_id in output_index_map:
            print("  Already exists in output, skipped.")
            continue

        if not isinstance(description, str) or not description.strip():
            extract_result = {
                "extract_platform_CVE": []
            }
            print("  Description is empty, write empty result.")
        else:
            try:
                extract_result = call_llm_extract(description)
                print(f"  extract_platform_CVE: {extract_result['extract_platform_CVE']}")
            except Exception as e:
                print(f"  Extraction failed: {e}")
                extract_result = {
                    "extract_platform_CVE": []
                }

        new_item = dict(item)
        new_item.update(extract_result)

        output_data.append(new_item)
        output_index_map[cve_id] = len(output_data) - 1
        save_json(output_path, output_data)

        print(f"  Written to output: {output_path.name}")

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    print(f"Done: {output_path}")


# =========================
# Main
# =========================
def main():
    input_dir = Path(INPUT_DIR)
    output_dir = Path(OUTPUT_DIR)

    all_files = [f"CVES_part_{i:02d}.json" for i in range(1, 26)]

    started = RESUME_FILE is None

    for filename in all_files:
        input_path = input_dir / filename
        output_path = output_dir / filename

        if not input_path.exists():
            print(f"Skipped: {input_path} does not exist")
            continue

        if not started:
            if filename == RESUME_FILE:
                started = True
            else:
                print(f"Skipped (before resume point): {filename}")
                continue

        if filename == RESUME_FILE:
            process_one_file(input_path, output_path, resume_cve_id=RESUME_CVE_ID)
        else:
            process_one_file(input_path, output_path, resume_cve_id=None)

    print("\nAll files finished.")


if __name__ == "__main__":
    main()