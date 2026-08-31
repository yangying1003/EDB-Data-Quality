import os
import re
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI


# =========================
# Basic Config
# =========================

# 输入文件：只处理这一个 JSON 文件
INPUT_JSON = r"EDB_undated.json"

# 输出文件：提取 date 后写入这里
OUTPUT_JSON = r"EDB_undated_date.json"

# 断点续跑设置
# None 表示自动从第一条未成功处理的记录开始
RESUME_EDB_ID = None
# 例如：
# RESUME_EDB_ID = "47097"

MODEL_NAME = "qwen3.5-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# 请求间隔与重试
SLEEP_BETWEEN_REQUESTS = 0.5
MAX_RETRIES = 3
RETRY_DELAY = 2

# 是否打印模型原始输出
PRINT_RAW_RESPONSE = False


# =========================
# Text Length Control
# =========================

MAX_LINES = 1800
MAX_CHARS = 80000


# =========================
# Thinking / Token Monitor
# =========================

# 注意：如果你所用模型不支持 thinking，请保持 False
ENABLE_THINKING = False
THINKING_BUDGET = 50

TOTAL_PROMPT_TOKENS = 0
TOTAL_COMPLETION_TOKENS = 0
TOTAL_TOKENS = 0


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
# Prompt
# =========================

def build_prompt(description: str) -> str:
    return f"""Extract all explicit dates from the following Exploit-DB PoC report.

Only extract dates related to the exploit, vulnerability, disclosure, advisory, publication, update, testing, or report creation.

Rules:
- Use only the provided text.
- Do not guess.
- Do not extract CVE IDs, versions, ports, IPs, or code numbers as dates.
- Normalize clear dates to YYYY-MM-DD.
- Use YYYY-MM for year-month only.
- Use YYYY for year only.
- Use null if the date is ambiguous.
- If no date is found, return an empty array.
- Output valid JSON only.

Date types:
exploit_date, disclosure_date, discovery_date, advisory_date, report_date, update_date, vendor_release_date, tested_date, unknown_date

JSON format:
{{
  "extract_dates": [
    {{
      "date_original": "",
      "date_normalized": "",
      "date_type": "",
      "evidence": ""
    }}
  ],
  "primary_date": null,
  "reason": ""
}}

Field meanings:
- date_original: exact date expression from the report
- date_normalized: normalized date, or null if ambiguous
- date_type: one of the date type labels above
- evidence: short original text showing the date
- primary_date: the most representative exploit/vulnerability-related date, or null
- reason: brief reason for choosing primary_date

Exploit-DB PoC report:
{description}"""


# =========================
# Helpers: JSON
# =========================

def extract_json_text(text: str) -> str:
    """
    从模型输出中提取 JSON。
    兼容：
    1. 纯 JSON
    2. ```json ... ```
    3. 前后带少量解释文本
    """
    if not text:
        raise ValueError("Empty model output.")

    text = text.strip()

    # 去掉 markdown code fence
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.IGNORECASE).strip()
        text = re.sub(r"```$", "", text).strip()

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"JSON object not found in model output: {text}")

    return text[start:end + 1]


def safe_json_loads(json_text: str) -> Dict[str, Any]:
    """
    宽松解析模型返回的 JSON。
    主要解决：
    - Invalid control character
    - 字符串字段中出现未转义换行符
    - 字符串字段中出现未转义制表符
    """
    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        return json.loads(json_text, strict=False)


def ensure_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def ensure_nullable_str(value: Any) -> Optional[str]:
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.lower() in {"null", "none", "n/a", "na", "unknown"}:
        return None

    return value


def normalize_date_type(value: Any) -> str:
    allowed = {
        "exploit_date",
        "disclosure_date",
        "discovery_date",
        "advisory_date",
        "report_date",
        "update_date",
        "vendor_release_date",
        "tested_date",
        "unknown_date"
    }

    value = ensure_str(value).lower()

    if value in allowed:
        return value

    mapping = {
        "exploit": "exploit_date",
        "poc_date": "exploit_date",
        "publication_date": "exploit_date",
        "published_date": "exploit_date",
        "submit_date": "exploit_date",
        "submitted_date": "exploit_date",
        "release_date": "exploit_date",

        "disclosure": "disclosure_date",
        "disclosed": "disclosure_date",
        "public_disclosure": "disclosure_date",

        "discovery": "discovery_date",
        "discovered": "discovery_date",

        "advisory": "advisory_date",
        "bulletin": "advisory_date",

        "report": "report_date",
        "created": "report_date",
        "writeup": "report_date",

        "update": "update_date",
        "updated": "update_date",
        "modified": "update_date",
        "revision": "update_date",

        "vendor": "vendor_release_date",
        "patch": "vendor_release_date",
        "fix": "vendor_release_date",

        "tested": "tested_date",
        "verified": "tested_date",

        "unknown": "unknown_date"
    }

    return mapping.get(value, "unknown_date")


def normalize_extract_dates(value: Any) -> List[Dict[str, Any]]:
    if value is None:
        return []

    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if not isinstance(item, dict):
            continue

        date_original = ensure_str(item.get("date_original"))
        date_normalized = ensure_nullable_str(item.get("date_normalized"))
        date_type = normalize_date_type(item.get("date_type"))
        evidence = ensure_str(item.get("evidence"))

        if not date_original:
            continue

        result.append({
            "date_original": date_original,
            "date_normalized": date_normalized,
            "date_type": date_type,
            "evidence": evidence
        })

    deduped = []
    seen = set()

    for item in result:
        key = (
            item.get("date_original"),
            item.get("date_normalized"),
            item.get("date_type"),
            item.get("evidence")
        )

        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return deduped


def empty_extract_result() -> Dict[str, Any]:
    return {
        "extract_dates": [],
        "primary_date": None,
        "date_reason": ""
    }


def normalize_result(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return empty_extract_result()

    return {
        "extract_dates": normalize_extract_dates(data.get("extract_dates")),
        "primary_date": ensure_nullable_str(data.get("primary_date")),
        "date_reason": ensure_str(data.get("reason"))
    }


# =========================
# Helpers: Token
# =========================

def get_usage_value(usage, key: str) -> int:
    if usage is None:
        return 0

    if isinstance(usage, dict):
        return int(usage.get(key, 0) or 0)

    return int(getattr(usage, key, 0) or 0)


def print_token_info(
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    thinking_requested: bool,
    reasoning_detected: bool
):
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
# Field Access
# =========================

def get_record_id(item: Dict[str, Any]) -> str:
    """
    读取 EDB_id。
    如果你的字段名不同，可以在这里继续加。
    """
    return ensure_str(
        item.get("EDB_id")
        or item.get("EDB_ID")
        or item.get("edb_id")
        or item.get("EDB-ID")
        or ""
    )


def get_title(item: Dict[str, Any]) -> str:
    return ensure_str(
        item.get("Title")
        or item.get("title")
        or item.get("Exploit Title")
        or item.get("exploit_title")
        or item.get("edb_title")
        or ""
    )


def get_structured_date(item: Dict[str, Any]) -> str:
    return ensure_str(
        item.get("Date")
        or item.get("date")
        or item.get("EDB_Date")
        or item.get("edb_date")
        or item.get("structured_date")
        or ""
    )


def get_description(item: Dict[str, Any]) -> str:
    """
    读取 PoC 文本。
    如果你的 PoC 字段名不同，可以在这里继续加。
    """
    return ensure_str(
        item.get("poc")
        or item.get("POC")
        or item.get("PoC")
        or item.get("edb_poc")
        or item.get("text")
        or item.get("content")
        or item.get("description")
        or ""
    )


def clean_poc_text(text: str) -> str:
    if not text:
        return ""

    lines = text.splitlines()
    cleaned_lines = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # 删除纯符号行
        if re.fullmatch(r"[\s/*#\-_=~`!@\$%\^&\(\)\[\]\{\};:,.<>|\\]+", line):
            continue

        cleaned_lines.append(line)

        if len(cleaned_lines) >= MAX_LINES:
            break

    cleaned_text = "\n".join(cleaned_lines)

    if len(cleaned_text) > MAX_CHARS:
        cleaned_text = cleaned_text[:MAX_CHARS]

    return cleaned_text


def build_input_text(item: Dict[str, Any]) -> str:
    """
    输入给模型的文本。
    默认加入 Title 和 PoC。
    默认不加入结构化 Date，避免模型直接照抄结构化字段。
    """
    title = get_title(item)
    poc = get_description(item)

    text_parts = []

    if title:
        text_parts.append(f"Exploit Title: {title}")

    if poc:
        text_parts.append(poc)

    return clean_poc_text("\n".join(text_parts))


# =========================
# LLM Call
# =========================

def call_llm_extract_date(description: str) -> Dict[str, Any]:
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
                if getattr(chunk, "usage", None) is not None:
                    usage = chunk.usage

                if not getattr(chunk, "choices", None):
                    continue

                delta = chunk.choices[0].delta

                reasoning_content = getattr(delta, "reasoning_content", None)
                if reasoning_content:
                    reasoning_detected = True

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

            # 这里使用宽松 JSON 解析，解决 Invalid control character
            data = safe_json_loads(json_text)

            normalized = normalize_result(data)

            normalized["_raw_date_response"] = answer_content
            normalized["_usage_date"] = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            normalized["_reasoning_detected"] = reasoning_detected

            return normalized

        except Exception as e:
            last_error = e
            print(f"  Attempt {attempt}/{MAX_RETRIES} failed: {e}")

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    raise RuntimeError(f"Model call failed after retries: {last_error}")


# =========================
# File Helpers
# =========================

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


def load_input_json(path: Path) -> List[Dict[str, Any]]:
    """
    支持两种格式：
    1. 顶层是 list:
       [{...}, {...}]

    2. 顶层是 dict，并且里面有 data / records / items 字段：
       {"data": [{...}, {...}]}
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ["data", "records", "items"]:
            if key in data and isinstance(data[key], list):
                return data[key]

    raise ValueError(f"Input file {path} top-level structure is not a list.")


def find_index_by_edb_id(data: List[Dict[str, Any]], edb_id: str) -> int:
    for i, item in enumerate(data):
        item_edb_id = get_record_id(item)
        if item_edb_id == edb_id:
            return i

    return -1


def build_output_index_map(output_data: List[Dict[str, Any]]) -> Dict[str, int]:
    mapping = {}

    for i, item in enumerate(output_data):
        edb_id = get_record_id(item)

        if edb_id:
            mapping[edb_id] = i

    return mapping


def get_success_processed_ids(output_data: List[Dict[str, Any]]) -> set:
    """
    只把 date_success=True 的记录视为已经成功处理。
    date_success=False 的记录后续会重跑。
    """
    processed_success_ids = set()

    for item in output_data:
        edb_id = get_record_id(item)

        if edb_id and item.get("date_success") is True:
            processed_success_ids.add(edb_id)

    return processed_success_ids


# =========================
# Process Single File
# =========================

def process_single_file(
    input_path: Path,
    output_path: Path,
    resume_edb_id: Optional[str] = None
):
    print("\n" + "=" * 80)
    print(f"Processing file: {input_path}")

    input_data = load_input_json(input_path)

    output_data = load_json_if_exists(output_path)
    output_index_map = build_output_index_map(output_data)

    start_index = 0

    # 指定某个 EDB_id 断点
    if resume_edb_id is not None:
        input_resume_index = find_index_by_edb_id(input_data, resume_edb_id)

        if input_resume_index == -1:
            raise ValueError(f"Resume EDB_id not found in input file: {resume_edb_id}")

        start_index = input_resume_index
        print(f"Resume from EDB_id: {resume_edb_id}, input index: {start_index + 1}")

    # 未指定 EDB_id 时，自动跳过前面已经成功处理的记录
    else:
        if output_data:
            processed_success_ids = get_success_processed_ids(output_data)

            while start_index < len(input_data):
                edb_id = get_record_id(input_data[start_index])

                if edb_id in processed_success_ids:
                    start_index += 1
                else:
                    break

            if start_index > 0:
                print(f"Existing successful output detected. Resume from record {start_index + 1}.")

    total = len(input_data)

    file_success = 0
    file_failed = 0
    file_skipped = 0
    file_retried = 0

    for idx in range(start_index, total):
        item = input_data[idx]

        edb_id = get_record_id(item)
        structured_date = get_structured_date(item)
        description = build_input_text(item)

        print("\n" + "-" * 80)
        print(f"[{idx + 1}/{total}] EDB_id = {edb_id}")
        print(f"Structured Date = {structured_date}")

        if not edb_id:
            file_skipped += 1
            print("  Missing EDB_id, skipped.")
            continue

        # 如果已经成功处理，跳过
        # 如果之前失败，则重跑并覆盖
        if edb_id in output_index_map:
            old_item = output_data[output_index_map[edb_id]]

            if old_item.get("date_success") is True:
                file_skipped += 1
                print("  Already successful in output, skipped.")
                continue
            else:
                file_retried += 1
                print("  Existing record failed before, retry and overwrite.")

        if not isinstance(description, str) or not description.strip():
            extract_result = empty_extract_result()
            success = False
            error = "Empty PoC text"
            print("  Description is empty, write empty date result.")

        else:
            try:
                extract_result = call_llm_extract_date(description)
                success = True
                error = None

                print(f"  extract_dates : {extract_result['extract_dates']}")
                print(f"  primary_date  : {extract_result['primary_date']}")
                print(f"  date_reason   : {extract_result['date_reason']}")

            except Exception as e:
                print(f"  Date extraction failed: {e}")

                extract_result = empty_extract_result()
                success = False
                error = str(e)

        new_item = dict(item)

        new_item.update({
            "structured_date": structured_date,

            "extract_dates": extract_result["extract_dates"],
            "primary_date": extract_result["primary_date"],
            "date_reason": extract_result["date_reason"],

            "date_success": success,
            "date_error": error,

            "raw_date_response": extract_result.get("_raw_date_response", ""),
            "usage_date": extract_result.get("_usage_date", {}),
            "reasoning_detected": extract_result.get("_reasoning_detected", False),

            "date_model": MODEL_NAME,
            "date_updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        })

        # 如果该 EDB_id 已经在输出文件中，则覆盖旧记录
        # 否则追加新记录
        if edb_id in output_index_map:
            output_data[output_index_map[edb_id]] = new_item
        else:
            output_data.append(new_item)
            output_index_map[edb_id] = len(output_data) - 1

        # 每处理完一条立即保存，防止中途崩溃丢数据
        save_json(output_path, output_data)

        if success:
            file_success += 1
        else:
            file_failed += 1

        print(f"  Written to output: {output_path}")

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    print("\n" + "=" * 80)
    print("Done.")
    print(f"Success : {file_success}")
    print(f"Failed  : {file_failed}")
    print(f"Skipped : {file_skipped}")
    print(f"Retried : {file_retried}")
    print(f"Output  : {output_path}")


# =========================
# Main
# =========================

def main():
    input_path = Path(INPUT_JSON)
    output_path = Path(OUTPUT_JSON)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    process_single_file(
        input_path=input_path,
        output_path=output_path,
        resume_edb_id=RESUME_EDB_ID
    )

    print("\n" + "=" * 80)
    print("All finished.")
    print(f"Input file  : {INPUT_JSON}")
    print(f"Output file : {OUTPUT_JSON}")


if __name__ == "__main__":
    main()