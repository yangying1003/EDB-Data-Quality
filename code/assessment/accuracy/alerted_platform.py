from pymongo import MongoClient
from collections import Counter
from pathlib import Path
import json


# =========================
# MongoDB 配置
# =========================
MONGO_URI = "mongodb://localhost:27017/"

DB_NAME = "Multiple_DB"
COLLECTION_NAME = "Merge_DB_platform_score"

OUTPUT_SUMMARY_TXT = Path("platform_alert_EDB_s_EDB_us_summary.txt")
OUTPUT_DETAIL_JSONL = Path("platform_alert_EDB_s_EDB_us_detail.jsonl")


# =========================
# Platform 告警规则
# =========================
RED_SCORES = {-2200, -2100, -2000, -1500, -1300}
ORANGE_SCORES = {-800}


client = MongoClient(MONGO_URI)
col = client[DB_NAME][COLLECTION_NAME]


def normalize_id(value):
    if value is None:
        return ""
    return str(value).strip()


def safe_score(value):
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return None


def classify_alert_level(score):
    """
    Platform 告警规则：
    score ∈ {-2200, -2100, -2000, -1500, -1300} -> red
    score = -800 -> orange
    其他分数 -> normal
    """
    score = safe_score(score)

    if score is None:
        return "normal"

    if score in RED_SCORES:
        return "red"

    if score in ORANGE_SCORES:
        return "orange"

    return "normal"


def json_default(obj):
    return str(obj)


def main():
    target_sources = ["EDB_s", "EDB_us"]

    stats = {
        source: {
            "alert_item_count": 0,
            "doc_ids": set(),
            "edb_ids": set(),
            "cve_ids": set(),
            "red_count": 0,
            "orange_count": 0,
            "platform_counter": Counter(),
            "score_counter": Counter(),
            "candidate_status_counter": Counter(),
        }
        for source in target_sources
    }

    total_docs = 0
    docs_with_edb_s_or_edb_us_alert = set()

    projection = {
        "_id": 1,
        "CVE-ID": 1,
        "edb_id": 1,
        "edb_title": 1,
        "platform_score_items": 1,
    }

    detail_fp = OUTPUT_DETAIL_JSONL.open("w", encoding="utf-8")

    cursor = col.find({}, projection, no_cursor_timeout=True)

    try:
        for doc in cursor:
            total_docs += 1

            doc_id = str(doc.get("_id"))
            edb_id = normalize_id(doc.get("edb_id"))
            cve_id = normalize_id(doc.get("CVE-ID"))
            edb_title = doc.get("edb_title", "")

            items = doc.get("platform_score_items", [])

            if not isinstance(items, list):
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue

                target_source = item.get("target_source")

                # 只统计 EDB_s 和 EDB_us
                if target_source not in target_sources:
                    continue

                score = safe_score(item.get("score"))
                alert_level = classify_alert_level(score)

                # 只统计橙色和红色告警
                if alert_level not in {"orange", "red"}:
                    continue

                platform = normalize_id(item.get("platform"))
                candidate_status = normalize_id(item.get("candidate_status"))

                stats[target_source]["alert_item_count"] += 1
                stats[target_source]["doc_ids"].add(doc_id)

                if edb_id:
                    stats[target_source]["edb_ids"].add(edb_id)

                if cve_id:
                    stats[target_source]["cve_ids"].add(cve_id)

                if alert_level == "red":
                    stats[target_source]["red_count"] += 1
                elif alert_level == "orange":
                    stats[target_source]["orange_count"] += 1

                if platform:
                    stats[target_source]["platform_counter"][platform] += 1

                if score is not None:
                    stats[target_source]["score_counter"][score] += 1

                if candidate_status:
                    stats[target_source]["candidate_status_counter"][candidate_status] += 1

                docs_with_edb_s_or_edb_us_alert.add(doc_id)

                detail_record = {
                    "doc_id": doc_id,
                    "edb_id": edb_id,
                    "cve_id": cve_id,
                    "edb_title": edb_title,
                    "target_source": target_source,
                    "target_field": item.get("target_field"),
                    "platform": platform,
                    "score": score,
                    "alert_level": alert_level,
                    "candidate_status": candidate_status,
                    "score_meaning": item.get("score_meaning", ""),
                    "target_values": item.get("target_values", []),
                    "details": item.get("details", []),
                }

                detail_fp.write(
                    json.dumps(detail_record, ensure_ascii=False, default=json_default)
                    + "\n"
                )

    finally:
        cursor.close()
        detail_fp.close()

    lines = []

    lines.append("=" * 80)
    lines.append("Platform 告警统计：EDB_s 与 EDB_us")
    lines.append("=" * 80)
    lines.append(f"数据库集合: {DB_NAME}.{COLLECTION_NAME}")
    lines.append(f"总文档数: {total_docs}")
    lines.append(f"红色告警分数: {sorted(RED_SCORES)}")
    lines.append(f"橙色告警分数: {sorted(ORANGE_SCORES)}")
    lines.append(
        f"存在 EDB_s 或 EDB_us 橙色/红色告警的文档数: "
        f"{len(docs_with_edb_s_or_edb_us_alert)}"
    )
    lines.append("")

    for source in target_sources:
        s = stats[source]

        lines.append("-" * 80)
        lines.append(f"{source} Platform 告警统计")
        lines.append("-" * 80)
        lines.append(f"告警次数总计: {s['alert_item_count']}")
        lines.append(f"红色告警次数: {s['red_count']}")
        lines.append(f"橙色告警次数: {s['orange_count']}")
        lines.append(f"存在告警的文档数: {len(s['doc_ids'])}")
        lines.append(f"涉及不同 EDB_ID 数量: {len(s['edb_ids'])}")
        lines.append(f"涉及不同 CVE-ID 数量: {len(s['cve_ids'])}")
        lines.append("")

        lines.append("candidate_status 分布:")
        if s["candidate_status_counter"]:
            for k, v in s["candidate_status_counter"].most_common():
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  无")
        lines.append("")

        lines.append("告警 score 分布:")
        if s["score_counter"]:
            for k, v in s["score_counter"].most_common():
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  无")
        lines.append("")

        lines.append("告警 platform Top 30:")
        if s["platform_counter"]:
            for k, v in s["platform_counter"].most_common(30):
                lines.append(f"  {k}: {v}")
        else:
            lines.append("  无")
        lines.append("")

    lines.append("=" * 80)
    lines.append(f"统计结果已保存到: {OUTPUT_SUMMARY_TXT.resolve()}")
    lines.append(f"详细告警记录已保存到: {OUTPUT_DETAIL_JSONL.resolve()}")
    lines.append("=" * 80)

    summary_text = "\n".join(lines)

    print(summary_text)
    OUTPUT_SUMMARY_TXT.write_text(summary_text, encoding="utf-8")


if __name__ == "__main__":
    main()