# -*- coding: utf-8 -*-
"""
功能：
从 MongoDB 的 EDB_completeness.Multiple_Google 集合中读取 POC 字段，
调用阿里云百炼 / DashScope 大模型提取 Google Dork，
并将结果写回同一条 MongoDB 文档的 add_Google 字段。

输入集合：
EDB_completeness.Multiple_Google

输入字段：
POC

输出字段：
add_Google

说明：
1. 只抽取 PoC 文本中明确出现的 Google Dork。
2. 不根据标题、厂商、软件名、CVE、漏洞描述自动生成 Google Dork。
3. 如果没有明确 Google Dork，则 add_Google 写入 None。
4. 每处理一条都会输出处理结果。
"""

import os
import re
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo import MongoClient, ASCENDING
from openai import OpenAI
from tqdm import tqdm


# =========================
# 1. Basic Config
# =========================

MONGO_URI = "mongodb://localhost:27017"

SOURCE_DB = "EDB_completeness"
SOURCE_COLL = "Multiple_Google"

POC_FIELD = "POC"
OUTPUT_FIELD = "add_Google"

MODEL_NAME = "qwen3.5-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

# 是否覆盖已经存在 add_Google 的文档
# False：跳过已处理文档
# True ：重新提取并覆盖
OVERWRITE_EXISTING = False

# 为避免 PoC 太长导致 token 过多，只截取前面部分
MAX_POC_CHARS = 120000

# 每次请求间隔
SLEEP_BETWEEN_REQUESTS = 0.5

MAX_RETRIES = 3
RETRY_DELAY = 2

PRINT_RAW_RESPONSE = False

# 是否保存证据、置信度等辅助字段
SAVE_AUDIT_FIELDS = True

# 是否先用规则找候选行
# True：只有发现 Google Dork / Dork / inurl: / intitle: 等候选内容时才调用大模型
# False：每条 POC 都调用大模型
ONLY_CALL_LLM_WHEN_CANDIDATE_EXISTS = False

# 每批处理多少条，避免 MongoDB 长游标超时
BATCH_SIZE = 1000

# 只测试前 N 条；None 表示全部
# 建议第一次先 LIMIT = 20 测试
LIMIT = None
# LIMIT = 20


# =========================
# 2. Thinking / Token Monitor
# =========================

ENABLE_THINKING = False
THINKING_BUDGET = 50

TOTAL_PROMPT_TOKENS = 0
TOTAL_COMPLETION_TOKENS = 0
TOTAL_TOKENS = 0


# =========================
# 3. Init Clients
# =========================

api_key = os.getenv("DASHSCOPE_API_KEY")

if not api_key:
    raise ValueError("DASHSCOPE_API_KEY environment variable is not set.")

client = OpenAI(
    api_key=api_key,
    base_url=BASE_URL,
    timeout=60,
    max_retries=1,
)

mongo_client = MongoClient(MONGO_URI)
collection = mongo_client[SOURCE_DB][SOURCE_COLL]


# =========================
# 4. Google Dork Rules
# =========================

INVALID_VALUES = {
    "",
    "unknown",
    "none",
    "null",
    "n/a",
    "na",
    "not found",
    "not specified",
    "unspecified",
    "not applicable",
    "no",
    "nil",
    "-",
    "--",
    "未提及",
    "未知",
    "无",
    "无法判断",
}

DORK_OPERATORS = [
    "inurl:",
    "allinurl:",
    "intitle:",
    "allintitle:",
    "intext:",
    "allintext:",
    "site:",
    "filetype:",
    "ext:",
    "cache:",
    "related:",
    "link:",
]

DORK_HINT_KEYWORDS = [
    "google dork",
    "google dorks",
    "dork",
    "dorks",
    "google search",
    "search query",
    "search string",
    "search term",
]


# =========================
# 5. Prompt
# =========================

def build_prompt(poc_text: str, candidate_lines: List[str]) -> str:
    """
    构造大模型提示词。
    如果存在候选行，则只把候选行交给模型，降低 token 和误判。
    如果不存在候选行但仍要求调用模型，则传入截断后的 POC。
    """
    if candidate_lines:
        input_text = "\n".join(candidate_lines)
        input_name = "Candidate lines from the PoC report"
    else:
        input_text = poc_text
        input_name = "PoC report"

    return f"""Extract Google Dork search queries from the following Exploit-DB PoC report.

Target field:
- add_Google: Google Dork search queries explicitly mentioned in the PoC report.

Important definitions:
1. Google Dork means a search query used to locate vulnerable pages, systems, files, or targets through Google or other search engines.
2. Valid Google Dork evidence may appear after headers such as:
   - Google Dork:
   - Google Dorks:
   - Dork:
   - Dorks:
   - Search Query:
   - Google Search:
3. Valid Google Dork expressions may also contain operators such as:
   - inurl:
   - allinurl:
   - intitle:
   - allintitle:
   - intext:
   - allintext:
   - site:
   - filetype:
   - ext:
   - cache:
   - related:
4. Only extract Google Dork values that are explicitly present in the provided text.
5. Do NOT generate, infer, rewrite, or guess a Google Dork from title, vendor, software name, CVE-ID, vulnerability type, or vulnerability description.
6. If the text says N/A, none, no, unknown, not applicable, or the field is empty, return null.
7. If multiple Google Dorks are clearly present, return all of them.
8. Preserve the original query text as much as possible, but remove labels such as "Google Dork:" or "Dork:".
9. Output valid JSON only. Do not output explanations or markdown.

Expected JSON format:
{{
  "add_Google": null,
  "evidence": [],
  "confidence": "low"
}}

If Google Dork exists:
{{
  "add_Google": ["inurl:admin.php"],
  "evidence": ["Google Dork: inurl:admin.php"],
  "confidence": "high"
}}

Field requirements:
- add_Google must be either null or a JSON array of strings.
- evidence must be a JSON array containing short original text evidence.
- confidence must be one of: "high", "medium", "low".

{input_name}:
{input_text}"""


# =========================
# 6. Helpers
# =========================

def truncate_poc_text(text: str, max_chars: int = MAX_POC_CHARS) -> str:
    """
    截断 PoC 文本，避免输入过长。
    """
    if not isinstance(text, str):
        return ""

    text = text.strip()

    if len(text) <= max_chars:
        return text

    return text[:max_chars] + "\n...[TRUNCATED]"


def clean_value(value: Any) -> str:
    """
    清理字符串。
    """
    if value is None:
        return ""

    value = str(value).strip()
    value = value.strip(" \"'`，。；;")
    value = value.strip("[](){}")
    value = re.sub(r"\s+", " ", value)

    return value.strip()


def has_dork_operator(text: str) -> bool:
    """
    判断文本是否包含典型 Google Dork 操作符。
    """
    lower_text = text.lower()
    return any(op in lower_text for op in DORK_OPERATORS)


def has_dork_hint(text: str) -> bool:
    """
    判断文本是否包含 Google Dork 相关提示词。
    """
    lower_text = text.lower()
    return any(keyword in lower_text for keyword in DORK_HINT_KEYWORDS)


def extract_candidate_lines(poc_text: str) -> List[str]:
    """
    从 POC 中抽取候选行。
    规则：
    1. 包含 Google Dork / Dork / Search Query 等提示词；
    2. 包含 inurl: / intitle: / site: 等 dork 操作符；
    3. 如果某一行是 Google Dork 标头，也额外保留其后两行，防止值写在下一行。
    """
    if not isinstance(poc_text, str) or not poc_text.strip():
        return []

    lines = poc_text.splitlines()
    candidate_lines = []

    for i, line in enumerate(lines):
        line_clean = line.strip()

        if not line_clean:
            continue

        if has_dork_hint(line_clean) or has_dork_operator(line_clean):
            candidate_lines.append(line_clean)

            # 如果当前行像是 Google Dork 标头，则把后面两行也加进来
            for j in range(i + 1, min(i + 3, len(lines))):
                next_line = lines[j].strip()
                if next_line:
                    candidate_lines.append(next_line)

    # 去重
    unique_lines = []
    seen = set()

    for line in candidate_lines:
        key = line.lower()
        if key not in seen:
            seen.add(key)
            unique_lines.append(line)

    return unique_lines


def extract_json_text(text: str) -> str:
    """
    从模型输出中提取 JSON。
    兼容：
    1. 纯 JSON
    2. ```json ... ```
    3. 前后带少量解释文字
    """
    if not text:
        raise ValueError("Empty model output.")

    text = text.strip()

    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
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
    """
    把模型返回值规范为字符串数组，并去重。
    """
    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, list):
        return []

    cleaned = []
    seen = set()

    for item in value:
        item = clean_value(item)

        if not item:
            continue

        if item.lower() in INVALID_VALUES:
            continue

        key = item.lower()
        if key not in seen:
            seen.add(key)
            cleaned.append(item)

    return cleaned


def validate_google_dorks(
    google_values: List[str],
    evidence: List[str],
    source_text: str
) -> List[str]:
    """
    二次校验模型输出，避免模型胡编。
    通过条件：
    1. 值本身包含 dork 操作符；
    2. 或该值确实出现在输入文本中；
    3. 或证据中含有 Google Dork / Dork 等明确标头。
    """
    valid = []
    seen = set()

    source_lower = source_text.lower()
    evidence_joined = "\n".join(evidence).lower()

    for item in google_values:
        value = clean_value(item)
        value_lower = value.lower()

        if not value:
            continue

        if value_lower in INVALID_VALUES:
            continue

        contains_operator = has_dork_operator(value)
        appears_in_source = value_lower in source_lower
        evidence_has_hint = has_dork_hint(evidence_joined)

        if not contains_operator and not appears_in_source and not evidence_has_hint:
            continue

        # 过滤明显不是查询语句的过短内容
        if len(value) < 3:
            continue

        if value_lower not in seen:
            seen.add(value_lower)
            valid.append(value)

    return valid


def normalize_google_result(data: Dict[str, Any], source_text: str) -> Dict[str, Any]:
    """
    规范模型结果。
    """
    google_values = ensure_str_list(
        data.get("add_Google")
        or data.get("google_dork")
        or data.get("Google_Dork")
        or data.get("google")
    )

    evidence = ensure_str_list(data.get("evidence"))

    confidence = str(data.get("confidence", "low")).strip().lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"

    google_values = validate_google_dorks(
        google_values=google_values,
        evidence=evidence,
        source_text=source_text
    )

    if not google_values:
        return {
            "add_Google": None,
            "evidence": evidence,
            "confidence": "low",
        }

    return {
        "add_Google": google_values,
        "evidence": evidence,
        "confidence": confidence,
    }


def empty_extract_result() -> Dict[str, Any]:
    """
    空结果。
    """
    return {
        "add_Google": None,
        "evidence": [],
        "confidence": "low",
    }


def get_usage_value(usage, key: str) -> int:
    """
    兼容 dict/object usage。
    """
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
    """
    打印 token 信息。
    """
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


def get_record_id(doc: Dict[str, Any]) -> str:
    """
    获取 EDB 记录 ID，便于打印日志。
    """
    return str(
        doc.get("EDB_id")
        or doc.get("edb_id")
        or doc.get("id")
        or doc.get("_id")
    )


# =========================
# 7. LLM Call
# =========================

def call_llm_extract_google(poc_text: str, candidate_lines: List[str]) -> Dict[str, Any]:
    """
    调用阿里云大模型提取 Google Dork。
    """
    global TOTAL_PROMPT_TOKENS, TOTAL_COMPLETION_TOKENS, TOTAL_TOKENS

    poc_text = truncate_poc_text(poc_text)
    source_text = "\n".join(candidate_lines) if candidate_lines else poc_text

    prompt = build_prompt(
        poc_text=poc_text,
        candidate_lines=candidate_lines
    )

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
                        "content": "You are a strict vulnerability information extraction assistant. Output JSON only."
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

            return normalize_google_result(data, source_text=source_text)

        except Exception as e:
            last_error = e
            print(f"  Attempt {attempt}/{MAX_RETRIES} failed: {e}", flush=True)

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    raise RuntimeError(f"Model call failed after retries: {last_error}")


# =========================
# 8. MongoDB Query / Update
# =========================

def build_base_query() -> Dict[str, Any]:
    """
    构造 MongoDB 查询条件。
    注意：不要写 {"$ne": None, "$ne": ""}，Python 字典会覆盖前一个 $ne。
    """
    base_query = {
        POC_FIELD: {
            "$exists": True,
            "$nin": [None, ""]
        }
    }

    if OVERWRITE_EXISTING:
        return base_query

    base_query[OUTPUT_FIELD] = {
        "$exists": False
    }

    return base_query


def update_document_with_result(
    doc: Dict[str, Any],
    result: Dict[str, Any],
    error: str = None,
    skipped_llm: bool = False
):
    """
    将结果写回 MongoDB。
    核心字段是 add_Google。
    """
    update_data = {
        OUTPUT_FIELD: result.get("add_Google"),
        "add_Google_updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "add_Google_model": MODEL_NAME,
        "add_Google_skipped_llm": skipped_llm,
    }

    if SAVE_AUDIT_FIELDS:
        update_data.update({
            "add_Google_evidence": result.get("evidence", []),
            "add_Google_confidence": result.get("confidence", "low"),
        })

    if error:
        update_data["add_Google_error"] = error
    else:
        update_data["add_Google_error"] = None

    collection.update_one(
        {"_id": doc["_id"]},
        {"$set": update_data}
    )


# =========================
# 9. Batch Cursor
# =========================

def fetch_batch(last_id: Optional[ObjectId], batch_size: int) -> List[Dict[str, Any]]:
    """
    分页获取 MongoDB 文档，避免长游标超时。
    """
    query = build_base_query()

    if last_id is not None:
        query["_id"] = {
            "$gt": last_id
        }

    cursor = collection.find(
        query,
        {
            "_id": 1,
            "EDB_id": 1,
            "edb_id": 1,
            "id": 1,
            POC_FIELD: 1
        }
    ).sort("_id", ASCENDING).limit(batch_size)

    return list(cursor)


# =========================
# 10. Main
# =========================

def main():
    base_query = build_base_query()
    total = collection.count_documents(base_query)

    if LIMIT is not None:
        total = min(total, LIMIT)

    print("=" * 80)
    print("EDB PoC Google Dork 提取任务开始")
    print(f"数据库集合: {SOURCE_DB}.{SOURCE_COLL}")
    print(f"输入字段: {POC_FIELD}")
    print(f"输出字段: {OUTPUT_FIELD}")
    print(f"模型: {MODEL_NAME}")
    print(f"覆盖已有结果: {OVERWRITE_EXISTING}")
    print(f"仅候选存在时调用LLM: {ONLY_CALL_LLM_WHEN_CANDIDATE_EXISTS}")
    print(f"预计处理数量: {total}")
    print("=" * 80, flush=True)

    success_count = 0
    empty_count = 0
    fail_count = 0
    skipped_llm_count = 0
    processed_count = 0

    last_id = None

    with tqdm(total=total) as pbar:
        while True:
            if LIMIT is not None and processed_count >= LIMIT:
                break

            current_batch_size = BATCH_SIZE

            if LIMIT is not None:
                current_batch_size = min(BATCH_SIZE, LIMIT - processed_count)

            docs = fetch_batch(last_id=last_id, batch_size=current_batch_size)

            if not docs:
                break

            for doc in docs:
                if LIMIT is not None and processed_count >= LIMIT:
                    break

                last_id = doc["_id"]
                processed_count += 1
                pbar.update(1)

                record_id = get_record_id(doc)
                poc_text = doc.get(POC_FIELD, "")

                print("\n" + "-" * 80, flush=True)
                print(f"[{processed_count}/{total}] Processing EDB record: {record_id}", flush=True)

                if not isinstance(poc_text, str) or not poc_text.strip():
                    result = empty_extract_result()
                    update_document_with_result(
                        doc=doc,
                        result=result,
                        skipped_llm=True
                    )

                    empty_count += 1
                    skipped_llm_count += 1

                    print(f"  POC is empty, write {OUTPUT_FIELD}=None", flush=True)
                    continue

                poc_text = truncate_poc_text(poc_text)
                candidate_lines = extract_candidate_lines(poc_text)

                print(f"  Candidate lines: {len(candidate_lines)}", flush=True)

                # 没有候选行，直接写 None
                if ONLY_CALL_LLM_WHEN_CANDIDATE_EXISTS and not candidate_lines:
                    result = empty_extract_result()
                    update_document_with_result(
                        doc=doc,
                        result=result,
                        skipped_llm=True
                    )

                    empty_count += 1
                    skipped_llm_count += 1

                    print(f"  No Google Dork candidate found, skip LLM.", flush=True)
                    print(f"  {OUTPUT_FIELD}: None", flush=True)
                    continue

                try:
                    print("  Calling LLM...", flush=True)

                    result = call_llm_extract_google(
                        poc_text=poc_text,
                        candidate_lines=candidate_lines
                    )

                    google_values = result.get("add_Google")

                    update_document_with_result(
                        doc=doc,
                        result=result,
                        skipped_llm=False
                    )

                    success_count += 1

                    if google_values:
                        print(f"  Extract success.", flush=True)
                        print(f"  {OUTPUT_FIELD}: {google_values}", flush=True)
                        print(f"  confidence: {result.get('confidence')}", flush=True)
                    else:
                        empty_count += 1
                        print(f"  Google Dork not found by LLM.", flush=True)
                        print(f"  {OUTPUT_FIELD}: None", flush=True)

                except Exception as e:
                    fail_count += 1
                    error_msg = str(e)

                    result = empty_extract_result()

                    update_document_with_result(
                        doc=doc,
                        result=result,
                        error=error_msg,
                        skipped_llm=False
                    )

                    print(f"  Extraction failed: {error_msg}", flush=True)
                    print(f"  {OUTPUT_FIELD}: None", flush=True)

                time.sleep(SLEEP_BETWEEN_REQUESTS)

    print("\n" + "=" * 80)
    print("EDB PoC Google Dork 提取任务完成")
    print(f"总处理数量: {processed_count}")
    print(f"成功调用并处理数量: {success_count}")
    print(f"add_Google 为空数量: {empty_count}")
    print(f"跳过 LLM 数量: {skipped_llm_count}")
    print(f"失败数量: {fail_count}")
    print(f"累计 Prompt Tokens: {TOTAL_PROMPT_TOKENS}")
    print(f"累计 Completion Tokens: {TOTAL_COMPLETION_TOKENS}")
    print(f"累计 Total Tokens: {TOTAL_TOKENS}")
    print("=" * 80)


if __name__ == "__main__":
    main()