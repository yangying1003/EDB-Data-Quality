import os
import re
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Set

from pymongo import MongoClient
from openai import OpenAI


# =========================
# Basic Config
# =========================

MONGO_URI = "mongodb://localhost:27017/"

# 输入集合：你的 EDB PoC 数据
INPUT_DB = "Multiple_DB"
INPUT_COLLECTION = "EDBS"

# 输出集合：新的数据库/新集合
OUTPUT_DB = "Multiple_DB"
OUTPUT_COLLECTION = "EDB_type_dual"

# 如果只想测试前 N 条，设置为数字；全部处理则为 None
LIMIT = None

# 是否跳过已经处理过的 EDB_id
SKIP_EXISTING = True

# Mongo 查询条件
# 如果想只处理部分数据，可以改这里，例如 {"Type": {"$exists": True}}
FILTER_QUERY = {}

MODEL_NAME = "qwen3.5-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# Request pacing
SLEEP_BETWEEN_REQUESTS = 0.5
MAX_RETRIES = 3
RETRY_DELAY = 2

# Whether to print raw model output
PRINT_RAW_RESPONSE = False

# =========================
# Text Length Control
# =========================

MAX_LINES = 300
MAX_CHARS = 20000


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
# Init MongoDB
# =========================

mongo_client = MongoClient(MONGO_URI)
input_col = mongo_client[INPUT_DB][INPUT_COLLECTION]
output_col = mongo_client[OUTPUT_DB][OUTPUT_COLLECTION]


# =========================
# Remote / Local Mapping Keywords
# =========================
# 用于 DoS -> CVE remote/local 的规则映射
# 你论文里可以写成：
# 若 PoC 中存在远程触发特征关键词，则 DoS 映射为 remote；
# 否则映射为 local。

REMOTE_KEYWORDS = [
    # 用户给定的关键词
    "http", "https", "router", "web", "sock", "socket",
    "ipv4", "ipv6", "ping", "port", "message",

    # 常见远程/网络触发词
    "remote", "remotely", "network", "tcp", "udp",
    "host", "server", "client", "packet", "request", "response",
    "url", "uri", "ftp", "ssh", "telnet", "smtp", "imap",
    "pop3", "dns", "rpc", "snmp", "ldap",

    # Web 攻击常见词
    "browser", "xss", "sql injection", "sqli",
    "csrf", "upload", "web application", "cms"
]

LOCAL_KEYWORDS = [
    "local", "locally", "local user", "authenticated user",
    "local access", "local privilege", "privilege escalation",
    "privesc", "root", "sudo", "setuid", "kernel",
    "shell", "terminal", "console", "execute locally"
]


# =========================
# Prompt
# =========================

def build_prompt(description: str) -> str:
    return f"""You are a vulnerability exploit metadata extraction assistant.

Your task is to extract the Exploit-DB Type from the given Exploit-DB PoC report.

You need to produce TWO levels of information:

Level 1: Exploit-DB Type
Extract one or more labels from the following Exploit-DB five-type taxonomy:
- remote
- local
- dos
- webapps
- hardware

Level 2: Evidence indicators for later CVE alignment
Do NOT directly infer CVE attack type. Only extract textual indicators that can support remote/local mapping.

Definitions of Exploit-DB Type:

1. remote
The exploit can be triggered remotely through a network service, protocol, port, socket, packet, HTTP request, remote input, or remote interaction.
Typical evidence includes:
remote service, network packet, socket, port, TCP/UDP, HTTP request, host, server, client, crafted packet, remote command execution.

2. local
The exploit requires local access, local execution, shell access, local user privileges, authenticated local user, local file access, or execution on the vulnerable machine.
Typical evidence includes:
local user, local privilege escalation, shell, terminal, root, sudo, setuid, kernel local exploit, local execution.

3. dos
The exploit mainly causes denial of service, crash, hang, memory exhaustion, service interruption, application unavailability, system reboot, or resource exhaustion.
Typical evidence includes:
denial of service, DoS, crash, segmentation fault, hang, panic, exhaustion, unavailable, service down.

4. webapps
The exploit targets a web application, website, CMS, web plugin, web panel, PHP/ASP/JSP application, CGI script, web endpoint, HTTP parameter, SQL injection, XSS, file upload, authentication bypass, or other web-based software.
Typical evidence includes:
web application, PHP, ASP, JSP, CGI, CMS, WordPress, Joomla, Drupal, SQL injection, XSS, upload, admin panel, URL parameter.

5. hardware
The exploit targets hardware devices, firmware, routers, IoT devices, embedded devices, appliances, network devices, or physical devices.
Typical evidence includes:
router, firmware, IoT, embedded device, appliance, camera, printer, switch, gateway, hardware model.

Important rules:
1. Use only the provided PoC report.
2. Do not use external knowledge.
3. Do not guess missing information.
4. If the report supports multiple Exploit-DB types, return all supported labels.
5. If no Exploit-DB type can be determined, return an empty array.
6. The field "extract_edb_type_5" must only contain labels from:
   ["remote", "local", "dos", "webapps", "hardware"]
7. The field "remote_indicators" should contain short original text evidence showing remote/network/web access.
8. The field "local_indicators" should contain short original text evidence showing local execution/local access.
9. The field "dos_indicators" should contain short original text evidence showing crash, DoS, hang, or service interruption.
10. The field "webapps_indicators" should contain short original text evidence showing web application context.
11. The field "hardware_indicators" should contain short original text evidence showing hardware/firmware/device context.
12. Preserve the original wording as much as possible.
13. Output valid JSON only, with no explanation and no markdown.

Expected JSON format:
{{
  "extract_edb_type_5": [],
  "remote_indicators": [],
  "local_indicators": [],
  "dos_indicators": [],
  "webapps_indicators": [],
  "hardware_indicators": [],
  "evidence": [],
  "reason": ""
}}

Exploit-DB PoC report:
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


def normalize_edb_type_5(value: Any) -> List[str]:
    allowed = {"remote", "local", "dos", "webapps", "hardware"}

    mapping = {
        "remote": "remote",
        "remotely": "remote",
        "network": "remote",
        "network-based": "remote",
        "remote code execution": "remote",
        "rce": "remote",

        "local": "local",
        "locally": "local",
        "local privilege escalation": "local",
        "privilege escalation": "local",

        "dos": "dos",
        "denial of service": "dos",
        "denial-of-service": "dos",
        "crash": "dos",

        "web": "webapps",
        "webapp": "webapps",
        "webapps": "webapps",
        "web application": "webapps",
        "web applications": "webapps",
        "php": "webapps",
        "asp": "webapps",
        "jsp": "webapps",
        "cgi": "webapps",
        "xss": "webapps",
        "sql injection": "webapps",
        "sqli": "webapps",

        "hardware": "hardware",
        "firmware": "hardware",
        "router": "hardware",
        "iot": "hardware",
        "embedded": "hardware",
        "device": "hardware",
        "appliance": "hardware"
    }

    items = ensure_str_list(value)

    result = []
    for item in items:
        item_norm = item.strip().lower()

        if item_norm in allowed:
            label = item_norm
        else:
            label = mapping.get(item_norm)

        if label and label not in result:
            result.append(label)

    return result


def empty_extract_result() -> Dict[str, Any]:
    return {
        "extract_edb_type_5": [],
        "remote_indicators": [],
        "local_indicators": [],
        "dos_indicators": [],
        "webapps_indicators": [],
        "hardware_indicators": [],
        "evidence": [],
        "reason": ""
    }


def normalize_result(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return empty_extract_result()

    return {
        "extract_edb_type_5": normalize_edb_type_5(data.get("extract_edb_type_5")),
        "remote_indicators": ensure_str_list(data.get("remote_indicators")),
        "local_indicators": ensure_str_list(data.get("local_indicators")),
        "dos_indicators": ensure_str_list(data.get("dos_indicators")),
        "webapps_indicators": ensure_str_list(data.get("webapps_indicators")),
        "hardware_indicators": ensure_str_list(data.get("hardware_indicators")),
        "evidence": ensure_str_list(data.get("evidence")),
        "reason": str(data.get("reason") or "").strip()
    }


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
# Field Access
# =========================

def get_record_id(item: Dict[str, Any]) -> str:
    return str(
        item.get("EDB_id")
        or item.get("EDB_ID")
        or item.get("edb_id")
        or ""
    ).strip()


def get_title(item: Dict[str, Any]) -> str:
    return str(
        item.get("Title")
        or item.get("title")
        or item.get("Exploit Title")
        or ""
    ).strip()


def get_structured_type(item: Dict[str, Any]) -> str:
    return str(
        item.get("Type")
        or item.get("type")
        or ""
    ).strip()


def get_description(item: Dict[str, Any]) -> str:
    return str(
        item.get("poc")
        or item.get("POC")
        or item.get("PoC")
        or item.get("text")
        or item.get("content")
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
    注意：
    这里默认不把结构化 Type 放进 prompt，
    避免模型直接照抄 Type，影响后面做结构化字段 vs 非结构化文本一致性比较。

    如果你想让模型也参考结构化 Type，可以手动加入：
    text_parts.append(f"Structured Exploit-DB Type: {structured_type}")
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
# Keyword Matching
# =========================

def find_matched_keywords(text: str, keywords: List[str]) -> List[str]:
    if not text:
        return []

    text_lower = text.lower()
    matched = []

    for kw in keywords:
        if kw.lower() in text_lower:
            matched.append(kw)

    return list(dict.fromkeys(matched))


def has_remote_feature(text: str, remote_indicators: List[str]) -> bool:
    matched_keywords = find_matched_keywords(text, REMOTE_KEYWORDS)
    return bool(matched_keywords or remote_indicators)


def has_local_feature(text: str, local_indicators: List[str]) -> bool:
    matched_keywords = find_matched_keywords(text, LOCAL_KEYWORDS)
    return bool(matched_keywords or local_indicators)


# =========================
# EDB Type -> CVE Attacker Type Mapping
# =========================

def map_edb_type_to_cve_attackertype(
    edb_types: List[str],
    full_text: str,
    remote_indicators: List[str],
    local_indicators: List[str]
) -> Dict[str, Any]:
    """
    CVE 对齐规则：

    1. remote  -> remote
    2. local   -> local
    3. webapps -> remote
    4. dos:
       - 如果 PoC 中存在远程特征关键词，映射为 remote
       - 否则映射为 local
    5. hardware:
       - 不直接映射为 physical
       - 如果有远程特征，映射为 remote
       - 如果有本地特征，映射为 local
       - 否则为空
    """

    cve_types: Set[str] = set()
    mapping_details = []

    matched_remote_keywords = find_matched_keywords(full_text, REMOTE_KEYWORDS)
    matched_local_keywords = find_matched_keywords(full_text, LOCAL_KEYWORDS)

    remote_feature_found = bool(matched_remote_keywords or remote_indicators)
    local_feature_found = bool(matched_local_keywords or local_indicators)

    for t in edb_types:
        if t == "remote":
            cve_types.add("remote")
            mapping_details.append("EDB remote -> CVE remote")

        elif t == "local":
            cve_types.add("local")
            mapping_details.append("EDB local -> CVE local")

        elif t == "webapps":
            cve_types.add("remote")
            mapping_details.append("EDB webapps -> CVE remote because web application exploits are accessed through web-based interaction")

        elif t == "dos":
            if remote_feature_found:
                cve_types.add("remote")
                mapping_details.append("EDB dos -> CVE remote because remote/network/web indicators were found")
            else:
                cve_types.add("local")
                mapping_details.append("EDB dos -> CVE local because no remote/network/web indicator was found")

        elif t == "hardware":
            if remote_feature_found:
                cve_types.add("remote")
                mapping_details.append("EDB hardware -> CVE remote because remote/network/device access indicators were found")
            elif local_feature_found:
                cve_types.add("local")
                mapping_details.append("EDB hardware -> CVE local because local access indicators were found")
            else:
                mapping_details.append("EDB hardware was not mapped because physical/context-dependent types are excluded and no remote/local indicator was found")

    ordered_result = []
    for label in ["remote", "local"]:
        if label in cve_types:
            ordered_result.append(label)

    return {
        "extract_cve_attackertype": ordered_result,
        "remote_feature_found": remote_feature_found,
        "local_feature_found": local_feature_found,
        "matched_remote_keywords": matched_remote_keywords,
        "matched_local_keywords": matched_local_keywords,
        "mapping_details": mapping_details
    }


# =========================
# LLM Call
# =========================

def call_llm_extract(description: str) -> Dict[str, Any]:
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
            data = json.loads(json_text)
            normalized = normalize_result(data)

            normalized["_raw_response"] = answer_content
            normalized["_usage"] = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
            normalized["_reasoning_detected":] = reasoning_detected

            return normalized

        except Exception as e:
            last_error = e
            print(f"  Attempt {attempt}/{MAX_RETRIES} failed: {e}")

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    raise RuntimeError(f"Model call failed after retries: {last_error}")


# =========================
# Main Processing
# =========================

def main():
    output_col.create_index("EDB_id", unique=True)

    existing_ids = set()

    if SKIP_EXISTING:
        existing_ids = set(
            str(item.get("EDB_id"))
            for item in output_col.find(
                {"EDB_id": {"$exists": True}},
                {"EDB_id": 1, "_id": 0}
            )
        )
        print(f"Existing output records: {len(existing_ids)}")

    projection = {
        "EDB_id": 1,
        "EDB_ID": 1,
        "edb_id": 1,
        "Title": 1,
        "title": 1,
        "Exploit Title": 1,
        "Type": 1,
        "type": 1,
        "POC": 1,
        "PoC": 1,
        "poc": 1,
        "text": 1,
        "content": 1
    }

    cursor = input_col.find(FILTER_QUERY, projection, no_cursor_timeout=True).batch_size(20)

    if LIMIT is not None:
        cursor = cursor.limit(LIMIT)

    total_seen = 0
    total_success = 0
    total_failed = 0
    total_skipped = 0

    try:
        for item in cursor:
            total_seen += 1

            edb_id = get_record_id(item)
            structured_type = get_structured_type(item)

            if not edb_id:
                total_skipped += 1
                print(f"[SKIP] Missing EDB_id")
                continue

            if SKIP_EXISTING and edb_id in existing_ids:
                total_skipped += 1
                print(f"[SKIP] EDB_id={edb_id} already exists")
                continue

            description = build_input_text(item)

            print("\n" + "=" * 80)
            print(f"[{total_seen}] EDB_id = {edb_id}")
            print(f"Structured Type = {structured_type}")

            if not description.strip():
                extract_result = empty_extract_result()
                mapping_result = {
                    "extract_cve_attackertype": [],
                    "remote_feature_found": False,
                    "local_feature_found": False,
                    "matched_remote_keywords": [],
                    "matched_local_keywords": [],
                    "mapping_details": []
                }

                result_doc = {
                    "EDB_id": edb_id,
                    "source_object_id": str(item.get("_id")),
                    "structured_type": structured_type,

                    "extract_edb_type_5": extract_result["extract_edb_type_5"],
                    "extract_cve_attackertype": mapping_result["extract_cve_attackertype"],

                    "remote_indicators": extract_result["remote_indicators"],
                    "local_indicators": extract_result["local_indicators"],
                    "dos_indicators": extract_result["dos_indicators"],
                    "webapps_indicators": extract_result["webapps_indicators"],
                    "hardware_indicators": extract_result["hardware_indicators"],

                    "evidence": extract_result["evidence"],
                    "reason": "Empty PoC text.",

                    "remote_feature_found": False,
                    "local_feature_found": False,
                    "matched_remote_keywords": [],
                    "matched_local_keywords": [],
                    "mapping_details": [],

                    "success": False,
                    "error": "Empty PoC text",
                    "model": MODEL_NAME,
                    "updated_at": datetime.now()
                }

                output_col.update_one(
                    {"EDB_id": edb_id},
                    {"$set": result_doc},
                    upsert=True
                )

                total_failed += 1
                print("  Empty PoC text, write empty result.")
                continue

            try:
                extract_result = call_llm_extract(description)

                edb_type_5 = extract_result["extract_edb_type_5"]

                mapping_result = map_edb_type_to_cve_attackertype(
                    edb_types=edb_type_5,
                    full_text=description,
                    remote_indicators=extract_result["remote_indicators"],
                    local_indicators=extract_result["local_indicators"]
                )

                result_doc = {
                    "EDB_id": edb_id,
                    "source_object_id": str(item.get("_id")),

                    # 原始 EDB 结构化 Type，方便后面比较
                    "structured_type": structured_type,

                    # 第一种 Type：Exploit-DB 五分类
                    "extract_edb_type_5": edb_type_5,

                    # 第二种 Type：与 CVE 对齐后的攻击者类型
                    "extract_cve_attackertype": mapping_result["extract_cve_attackertype"],

                    # LLM 抽取的证据指标
                    "remote_indicators": extract_result["remote_indicators"],
                    "local_indicators": extract_result["local_indicators"],
                    "dos_indicators": extract_result["dos_indicators"],
                    "webapps_indicators": extract_result["webapps_indicators"],
                    "hardware_indicators": extract_result["hardware_indicators"],

                    "evidence": extract_result["evidence"],
                    "reason": extract_result["reason"],

                    # 规则映射细节
                    "remote_feature_found": mapping_result["remote_feature_found"],
                    "local_feature_found": mapping_result["local_feature_found"],
                    "matched_remote_keywords": mapping_result["matched_remote_keywords"],
                    "matched_local_keywords": mapping_result["matched_local_keywords"],
                    "mapping_details": mapping_result["mapping_details"],

                    # 原始模型输出和 token
                    "raw_response": extract_result.get("_raw_response", ""),
                    "usage": extract_result.get("_usage", {}),
                    "reasoning_detected": extract_result.get("_reasoning_detected", False),

                    "success": True,
                    "error": None,
                    "model": MODEL_NAME,
                    "updated_at": datetime.now()
                }

                output_col.update_one(
                    {"EDB_id": edb_id},
                    {"$set": result_doc},
                    upsert=True
                )

                total_success += 1

                print(f"  extract_edb_type_5      : {edb_type_5}")
                print(f"  extract_cve_attackertype: {mapping_result['extract_cve_attackertype']}")
                print(f"  remote_keywords         : {mapping_result['matched_remote_keywords']}")
                print(f"  local_keywords          : {mapping_result['matched_local_keywords']}")
                print(f"  mapping_details         : {mapping_result['mapping_details']}")
                print(f"  Written to MongoDB      : {OUTPUT_DB}.{OUTPUT_COLLECTION}")

            except Exception as e:
                total_failed += 1
                print(f"  Extraction failed: {e}")

                fail_doc = {
                    "EDB_id": edb_id,
                    "source_object_id": str(item.get("_id")),
                    "structured_type": structured_type,

                    "extract_edb_type_5": [],
                    "extract_cve_attackertype": [],

                    "remote_indicators": [],
                    "local_indicators": [],
                    "dos_indicators": [],
                    "webapps_indicators": [],
                    "hardware_indicators": [],

                    "evidence": [],
                    "reason": "",

                    "remote_feature_found": False,
                    "local_feature_found": False,
                    "matched_remote_keywords": [],
                    "matched_local_keywords": [],
                    "mapping_details": [],

                    "success": False,
                    "error": str(e),
                    "model": MODEL_NAME,
                    "updated_at": datetime.now()
                }

                output_col.update_one(
                    {"EDB_id": edb_id},
                    {"$set": fail_doc},
                    upsert=True
                )

            time.sleep(SLEEP_BETWEEN_REQUESTS)

    finally:
        cursor.close()

    print("\n" + "=" * 80)
    print("All MongoDB records finished.")
    print(f"Seen    : {total_seen}")
    print(f"Success : {total_success}")
    print(f"Failed  : {total_failed}")
    print(f"Skipped : {total_skipped}")
    print(f"Output  : {OUTPUT_DB}.{OUTPUT_COLLECTION}")


if __name__ == "__main__":
    main()