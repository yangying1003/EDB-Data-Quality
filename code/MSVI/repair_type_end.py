# -*- coding: utf-8 -*-
"""
Type 修正代码：只修正 EDB_s_type

核心逻辑：
1. 只要 edb_s_type 或 edb_us_type 中存在红色/橙色 Type 告警，
   就把该 score 文档放入待修正文档集合；
2. 对进入待修正集合的文档，修正对象只针对 EDB_s_type；
3. 把该文档中所有来源出现过的合法 Type 标签作为候选标签；
4. 用另外四个来源验证候选标签：
      edb_us_type、cves_5type、cnnvds_5type、nvds_5type
5. 如果某个候选标签至少被 2 个来源支持，则写入 repair_edb_s_type；
   否则不写入。
"""

from pymongo import MongoClient
from collections import defaultdict, Counter
from pathlib import Path
import json
import ast
import re
from typing import Any, Dict, List


# =========================================================
# 1. MongoDB 配置
# =========================================================

MONGO_URI = "mongodb://localhost:27017/"

SOURCE_DB = "Multiple_DB"

# 奖惩矩阵打分集合
SCORE_COLLECTION = "Merge_DB_type_score"

# 原始 Type 字段集合
RAW_COLLECTION = "Merge_DB_type"

# 输出数据库和集合
OUTPUT_DB = "EDB_imporve"
OUTPUT_COLLECTION = "EDB_s_type_repair_all_candidates_support2"

CLEAR_OUTPUT_BEFORE_RUN = True
BATCH_SIZE = 1000


# =========================================================
# 2. 告警阈值
# =========================================================

RED_THRESHOLD = -1800
ORANGE_THRESHOLD = -1500

# 至少两个来源支持，才写入修正字段
SUPPORT_MIN_COUNT = 2


# =========================================================
# 3. Type 标签体系
# =========================================================

ALLOWED_TYPES = {
    "remote",
    "local",
    "webapps",
    "dos",
    "hardware"
}

TYPE_ORDER = ["remote", "local", "webapps", "dos", "hardware"]


# =========================================================
# 4. 字段设置
# =========================================================

# 用于判断是否进入待修正文档的字段
ALERT_TARGET_FIELDS = [
    "edb_s_type",
    "edb_us_type"
]

# 修正对象
REPAIR_TARGET_FIELD = "edb_s_type"

# 支持验证来源：不使用 edb_s_type 自己
SUPPORT_COLUMNS = [
    "edb_us_type",
    "cves_5type",
    "cnnvds_5type",
    "nvds_5type"
]

# 生成候选标签时使用的所有来源
CANDIDATE_COLUMNS = [
    "edb_s_type",
    "edb_us_type",
    "cves_5type",
    "cnnvds_5type",
    "nvds_5type"
]


# =========================================================
# 5. Type 规范化函数
# =========================================================

EMPTY_VALUES = {
    "",
    "none",
    "null",
    "nan",
    "n/a",
    "na",
    "unknown",
    "undefined",
    "not specified",
    "not mentioned",
    "[]",
    "{}",
}

TYPE_ALIASES = {
    # remote
    "remote": "remote",
    "remotely": "remote",
    "network": "remote",
    "remote attacker": "remote",

    # local
    "local": "local",
    "locally": "local",
    "local attacker": "local",

    # webapps
    "web": "webapps",
    "webapp": "webapps",
    "webapps": "webapps",
    "web app": "webapps",
    "web apps": "webapps",
    "web application": "webapps",
    "web applications": "webapps",

    # dos
    "dos": "dos",
    "do s": "dos",
    "denial of service": "dos",
    "denial service": "dos",
    "denialofservice": "dos",

    # hardware
    "hardware": "hardware",
    "hw": "hardware",
    "device": "hardware",
    "physical": "hardware",
}


def normalize_type_label(value: Any) -> str | None:
    """
    将单个 Type 值规范化为五类标签之一。
    """

    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    text = text.strip("[]{}()'\"` ")
    text = text.lower()

    text = text.replace("_", " ")
    text = text.replace("-", " ")

    text = re.sub(r"[^a-z0-9\s]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    if text in EMPTY_VALUES:
        return None

    if text in TYPE_ALIASES:
        text = TYPE_ALIASES[text]

    if text in ALLOWED_TYPES:
        return text

    return None


def flatten_value(value: Any) -> List[Any]:
    """
    将 string / list / nested list / dict 递归展开为普通列表。
    """

    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        result = []
        for item in value:
            result.extend(flatten_value(item))
        return result

    if isinstance(value, dict):
        result = []
        for v in value.values():
            result.extend(flatten_value(v))
        return result

    if isinstance(value, str):
        s = value.strip()

        if s.lower() in EMPTY_VALUES:
            return []

        # 处理字符串形式数组，例如 '["remote", "webapps"]'
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("(") and s.endswith(")")):
            for parser in (json.loads, ast.literal_eval):
                try:
                    parsed = parser(s)
                    return flatten_value(parsed)
                except Exception:
                    pass

        # 处理 remote, local / remote;local / remote/local
        parts = re.split(r"[,，;；|/\n\r]+", s)
        return [p.strip() for p in parts if p.strip()]

    return [value]


def sort_type_values(values: Any) -> List[str]:
    """
    按固定 Type 顺序排序。
    """

    unique_values = list(set(values))

    return sorted(
        unique_values,
        key=lambda x: TYPE_ORDER.index(x) if x in TYPE_ORDER else 999
    )


def normalize_type_list(value: Any) -> List[str]:
    """
    将任意 Type 字段统一转换为去重后的 list[str]。
    """

    result = []

    for item in flatten_value(value):
        label = normalize_type_label(item)
        if label and label not in result:
            result.append(label)

    return sort_type_values(result)


# =========================================================
# 6. 分数与告警判断函数
# =========================================================

def safe_number(x: Any) -> int | float | None:
    """
    将分数安全转换为数字。
    """

    if isinstance(x, (int, float)):
        value = float(x)
        return int(value) if value.is_integer() else value

    if isinstance(x, str):
        x = x.strip()
        try:
            value = float(x)
            return int(value) if value.is_integer() else value
        except ValueError:
            return None

    return None


def get_alert_level(score: Any) -> str | None:
    """
    Type 告警规则：
        red: score <= -1800
        orange: score == -1500
    """

    score = safe_number(score)

    if score is None:
        return None

    if score <= RED_THRESHOLD:
        return "red"

    if score == ORANGE_THRESHOLD:
        return "orange"

    return None


# =========================================================
# 7. 原始文档查找
# =========================================================

def find_raw_doc(raw_col, score_doc: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    在 Multiple_DB.Merge_DB_type 中查找原始文档。

    优先级：
        1. source_doc_id
        2. CVE-ID + edb_id
        3. edb_id
        4. CVE-ID
    """

    source_doc_id = score_doc.get("source_doc_id")
    if source_doc_id is not None:
        raw_doc = raw_col.find_one({"_id": source_doc_id})
        if raw_doc:
            return raw_doc

    cve_id = score_doc.get("CVE-ID")
    edb_id = score_doc.get("edb_id")

    if cve_id is not None and edb_id is not None:
        raw_doc = raw_col.find_one({
            "CVE-ID": cve_id,
            "edb_id": edb_id
        })
        if raw_doc:
            return raw_doc

    if edb_id is not None:
        raw_doc = raw_col.find_one({"edb_id": edb_id})
        if raw_doc:
            return raw_doc

    if cve_id is not None:
        raw_doc = raw_col.find_one({"CVE-ID": cve_id})
        if raw_doc:
            return raw_doc

    return None


def build_type_fields(raw_doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    读取并规范化所有相关 Type 字段。
    """

    result = {}

    for col in CANDIDATE_COLUMNS:
        result[col] = normalize_type_list(raw_doc.get(col))

    return result


# =========================================================
# 8. 判断是否进入待修正文档
# =========================================================

def extract_alert_rows(score_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    从 type_score_rows 中提取 edb_s_type / edb_us_type 的告警行。

    注意：
        这里用于判断该文档是否进入待修正集合。
        只保留能够规范化为五类 Type 的告警标签。
    """

    result = []

    rows = score_doc.get("type_score_rows", [])

    if not isinstance(rows, list):
        return result

    for row in rows:
        field = row.get("field")
        if field not in ALERT_TARGET_FIELDS:
            continue

        score = safe_number(row.get("score"))
        alert_level = get_alert_level(score)

        if alert_level is None:
            continue

        raw_type = row.get("type")
        type_label = normalize_type_label(raw_type)

        # 非五类 Type 标签不进入 Type 修正
        if type_label is None:
            continue

        result.append({
            "field": field,
            "source_name": row.get("source_name"),
            "type": type_label,
            "raw_type": raw_type,
            "score": score,
            "alert_level": alert_level,
            "source_has_type": row.get("source_has_type"),
            "alert_kind": row.get("alert_kind")
        })

    return result


# =========================================================
# 9. 候选标签与支持验证
# =========================================================

def build_candidate_types(type_fields: Dict[str, List[str]]) -> List[str]:
    """
    把该文档所有来源出现过的合法 Type 标签作为候选标签。

    candidate_types =
        edb_s_type ∪ edb_us_type ∪ cves_5type ∪ cnnvds_5type ∪ nvds_5type
    """

    candidates = set()

    for col in CANDIDATE_COLUMNS:
        candidates.update(type_fields.get(col, []))

    return sort_type_values(candidates)


def collect_support_info(
    candidate: str,
    type_fields: Dict[str, List[str]]
) -> Dict[str, Any]:
    """
    用另外四个来源验证某个候选标签是否被支持。

    支持来源：
        edb_us_type、cves_5type、cnnvds_5type、nvds_5type

    支持条件：
        该来源字段中包含该候选标签。
    """

    support_sources = []
    support_details = {}

    for col in SUPPORT_COLUMNS:
        values = type_fields.get(col, [])
        supported = candidate in values

        if supported:
            support_sources.append(col)

        support_details[col] = {
            "values": values,
            "supported": supported
        }

    return {
        "candidate": candidate,
        "support_sources": support_sources,
        "support_count": len(support_sources),
        "support_details": support_details,
        "supported_by_two_or_more_sources": len(support_sources) >= SUPPORT_MIN_COUNT
    }


def build_repair_result(
    candidate_types: List[str],
    type_fields: Dict[str, List[str]]
) -> tuple[List[str], List[Dict[str, Any]]]:
    """
    对所有候选标签进行支持验证。
    至少两个来源支持的标签写入 repair_edb_s_type。
    """

    candidate_support_details = []
    repair_types = []

    for candidate in candidate_types:
        support_info = collect_support_info(candidate, type_fields)
        candidate_support_details.append(support_info)

        if support_info["supported_by_two_or_more_sources"]:
            repair_types.append(candidate)

    return sort_type_values(repair_types), candidate_support_details


def decide_repair_action(original_edb_s_type: List[str], repair_edb_s_type: List[str]) -> str:
    """
    判断对 EDB_s_type 的修正动作。
    """

    original_set = set(original_edb_s_type)
    repair_set = set(repair_edb_s_type)

    added = repair_set - original_set
    removed = original_set - repair_set

    if added and removed:
        return "replace_or_update"

    if added:
        return "add_supported_type"

    if removed:
        return "remove_unsupported_type"

    return "no_change"


# =========================================================
# 10. 主程序
# =========================================================

def main():
    client = MongoClient(MONGO_URI)

    score_col = client[SOURCE_DB][SCORE_COLLECTION]
    raw_col = client[SOURCE_DB][RAW_COLLECTION]
    output_col = client[OUTPUT_DB][OUTPUT_COLLECTION]

    if CLEAR_OUTPUT_BEFORE_RUN:
        output_col.delete_many({})
        print(f"[清空] {OUTPUT_DB}.{OUTPUT_COLLECTION}")

    total_score_docs = 0

    # 有 edb_s_type / edb_us_type 告警的 score 文档数
    alert_score_docs = 0

    # 找不到 raw_doc 的文档数
    missing_raw_docs = 0

    # 没有进入修正的文档数
    no_alert_docs = 0

    # 写入输出集合的待修正文档数
    inserted_repair_docs = 0

    # 统计
    alert_column_counter = Counter()
    alert_level_counter = Counter()
    alert_type_counter = Counter()

    candidate_type_counter = Counter()
    supported_type_counter = Counter()
    unsupported_type_counter = Counter()

    repair_type_counter = Counter()
    added_type_counter = Counter()
    removed_type_counter = Counter()
    action_counter = Counter()

    alert_edb_ids = set()
    changed_edb_ids = set()
    add_edb_ids = set()
    remove_edb_ids = set()
    no_change_edb_ids = set()

    batch = []

    cursor = score_col.find({}, no_cursor_timeout=True).batch_size(BATCH_SIZE)

    try:
        for score_doc in cursor:
            total_score_docs += 1

            # 1. 先判断 edb_s_type / edb_us_type 是否存在告警
            alert_rows = extract_alert_rows(score_doc)

            if not alert_rows:
                no_alert_docs += 1
                continue

            alert_score_docs += 1

            # 2. 查找原始 Type 字段
            raw_doc = find_raw_doc(raw_col, score_doc)

            if raw_doc is None:
                missing_raw_docs += 1
                continue

            type_fields = build_type_fields(raw_doc)

            original_edb_s_type = type_fields.get("edb_s_type", [])
            original_edb_us_type = type_fields.get("edb_us_type", [])

            # 3. 候选标签 = 该文档所有来源出现过的 Type 标签
            candidate_types = build_candidate_types(type_fields)

            # 4. 用另外四个来源验证候选标签，得到 repair_edb_s_type
            repair_edb_s_type, candidate_support_details = build_repair_result(
                candidate_types=candidate_types,
                type_fields=type_fields
            )

            added_type = sort_type_values(set(repair_edb_s_type) - set(original_edb_s_type))
            removed_type = sort_type_values(set(original_edb_s_type) - set(repair_edb_s_type))

            repair_action = decide_repair_action(
                original_edb_s_type=original_edb_s_type,
                repair_edb_s_type=repair_edb_s_type
            )

            edb_id = score_doc.get("edb_id") or raw_doc.get("edb_id")
            cve_id = score_doc.get("CVE-ID") or raw_doc.get("CVE-ID")

            if edb_id is not None:
                alert_edb_ids.add(str(edb_id))

            if added_type or removed_type:
                if edb_id is not None:
                    changed_edb_ids.add(str(edb_id))

            if added_type:
                if edb_id is not None:
                    add_edb_ids.add(str(edb_id))

            if removed_type:
                if edb_id is not None:
                    remove_edb_ids.add(str(edb_id))

            if not added_type and not removed_type:
                if edb_id is not None:
                    no_change_edb_ids.add(str(edb_id))

            # 5. 更新统计
            for row in alert_rows:
                alert_column_counter[row["field"]] += 1
                alert_level_counter[row["alert_level"]] += 1
                alert_type_counter[row["type"]] += 1

            for t in candidate_types:
                candidate_type_counter[t] += 1

            for item in candidate_support_details:
                if item["supported_by_two_or_more_sources"]:
                    supported_type_counter[item["candidate"]] += 1
                else:
                    unsupported_type_counter[item["candidate"]] += 1

            for t in repair_edb_s_type:
                repair_type_counter[t] += 1

            for t in added_type:
                added_type_counter[t] += 1

            for t in removed_type:
                removed_type_counter[t] += 1

            action_counter[repair_action] += 1

            # 6. 输出文档
            output_doc = {
                "source_score_doc_id": score_doc.get("_id"),
                "source_raw_doc_id": raw_doc.get("_id"),

                "CVE-ID": cve_id,
                "edb_id": edb_id,

                "edb_author": raw_doc.get("edb_author"),
                "edb_title": raw_doc.get("edb_title"),
                "edb_poc": raw_doc.get("edb_poc"),

                # 进入待修正的依据
                "alert_rows": alert_rows,
                "alert_target_fields": ALERT_TARGET_FIELDS,

                # 原始字段
                "original_type_fields": type_fields,
                "original_edb_s_type": original_edb_s_type,
                "original_edb_us_type": original_edb_us_type,

                # 候选标签
                "candidate_types": candidate_types,

                # 四个来源支持验证结果
                "support_columns": SUPPORT_COLUMNS,
                "candidate_support_details": candidate_support_details,

                # 最终修正结果：只修正 EDB_s_type
                "repair_target_field": REPAIR_TARGET_FIELD,
                "repair_edb_s_type": repair_edb_s_type,

                # 与原始 EDB_s_type 对比
                "added_type": added_type,
                "removed_type": removed_type,
                "type_repair_action": repair_action,

                # 原始分数信息，方便回溯
                "type_score_rows": score_doc.get("type_score_rows"),
                "type_column_scores": score_doc.get("type_column_scores"),

                "repair_rule": {
                    "step_1": (
                        "If edb_s_type or edb_us_type contains at least one red/orange "
                        "Type alert, the document is selected as a repair candidate."
                    ),
                    "step_2": (
                        "All Type labels appearing in edb_s_type, edb_us_type, CVE, "
                        "CNNVD and NVD are used as candidate labels."
                    ),
                    "step_3": (
                        "Each candidate label is verified by four support sources: "
                        "edb_us_type, cves_5type, cnnvds_5type and nvds_5type."
                    ),
                    "step_4": (
                        "A candidate label is written into repair_edb_s_type only if "
                        "it is supported by at least two sources."
                    ),
                    "formula": (
                        "repair_edb_s_type = {t in candidate_types | "
                        "support_count(t) >= 2}"
                    ),
                    "support_min_count": SUPPORT_MIN_COUNT,
                    "alert_rule": {
                        "red": "score <= -1800",
                        "orange": "score == -1500"
                    },
                    "allowed_types": TYPE_ORDER
                }
            }

            batch.append(output_doc)
            inserted_repair_docs += 1

            if len(batch) >= BATCH_SIZE:
                output_col.insert_many(batch)
                print(f"[写入] 已写入 {inserted_repair_docs} 条 EDB_s Type 修正文档")
                batch.clear()

    finally:
        cursor.close()

    if batch:
        output_col.insert_many(batch)
        print(f"[写入] 已写入 {inserted_repair_docs} 条 EDB_s Type 修正文档")

    # 创建索引
    output_col.create_index("edb_id")
    output_col.create_index("CVE-ID")
    output_col.create_index("repair_target_field")
    output_col.create_index("type_repair_action")
    output_col.create_index("repair_edb_s_type")
    output_col.create_index("added_type")
    output_col.create_index("removed_type")
    output_col.create_index("candidate_types")
    output_col.create_index("alert_rows.field")
    output_col.create_index("alert_rows.type")
    output_col.create_index("candidate_support_details.candidate")
    output_col.create_index("candidate_support_details.support_count")

    summary = {
        "score_collection": f"{SOURCE_DB}.{SCORE_COLLECTION}",
        "raw_collection": f"{SOURCE_DB}.{RAW_COLLECTION}",
        "output_collection": f"{OUTPUT_DB}.{OUTPUT_COLLECTION}",

        "repair_target_field": REPAIR_TARGET_FIELD,
        "alert_target_fields": ALERT_TARGET_FIELDS,
        "candidate_columns": CANDIDATE_COLUMNS,
        "support_columns": SUPPORT_COLUMNS,

        "total_score_docs": total_score_docs,
        "alert_score_docs": alert_score_docs,
        "inserted_repair_docs": inserted_repair_docs,
        "missing_raw_docs": missing_raw_docs,
        "no_alert_docs": no_alert_docs,

        "distinct_alert_edb_count": len(alert_edb_ids),
        "distinct_changed_edb_count": len(changed_edb_ids),
        "distinct_add_edb_count": len(add_edb_ids),
        "distinct_remove_edb_count": len(remove_edb_ids),
        "distinct_no_change_edb_count": len(no_change_edb_ids),

        "action_counter": dict(action_counter),

        "total_type_alert_count_by_row": sum(alert_column_counter.values()),
        "alert_column_counter": dict(alert_column_counter),
        "alert_level_counter": dict(alert_level_counter),
        "alert_type_counter": dict(alert_type_counter),

        "candidate_type_counter": dict(candidate_type_counter),
        "supported_type_counter": dict(supported_type_counter),
        "unsupported_type_counter": dict(unsupported_type_counter),

        "repair_type_counter": dict(repair_type_counter),
        "added_type_counter": dict(added_type_counter),
        "removed_type_counter": dict(removed_type_counter),

        "repair_rule": {
            "formula": (
                "repair_edb_s_type = {t in candidate_types | support_count(t) >= 2}"
            ),
            "support_min_count": SUPPORT_MIN_COUNT,
            "red_threshold": RED_THRESHOLD,
            "orange_threshold": ORANGE_THRESHOLD,
            "orange_rule": "score == -1500",
            "allowed_types": TYPE_ORDER
        }
    }

    print("\n========== EDB_s Type 修正统计 ==========")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    out_path = Path("EDB_s_type_repair_all_candidates_support2_summary.json")
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n统计结果已保存到: {out_path.resolve()}")
    print(f"修正结果已写入集合: {OUTPUT_DB}.{OUTPUT_COLLECTION}")

    client.close()


if __name__ == "__main__":
    main()