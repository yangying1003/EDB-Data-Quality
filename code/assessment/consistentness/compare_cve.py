from pymongo import MongoClient, UpdateOne
import csv
import re
from datetime import datetime

# =========================
# 配置区
# =========================
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "EDB_llm"
COLLECTION_NAME = "llmextract_cve"
OUTPUT_CSV = "cve_extract_cve_compare_end.csv"

# 是否把对比结果写回 MongoDB
WRITE_BACK_TO_MONGO = True

# 批量写入大小
BATCH_SIZE = 1000


def normalize_cve_field(value):
    """
    将 CVE_id / extract_cve 统一转成标准集合 set[str]
    处理情况：
    1. 单个 string: "2006-3677"
    2. 多个 array: ["2006-3677", "2006-3678"]
    3. 多个 string: "2006-3677, 2006-3678"
    4. 标准格式: "CVE-2006-3677"

    最终统一成:
    {"CVE-2006-3677", ...}
    """
    if value is None:
        return set()

    result = set()

    def extract_from_text(text):
        text = str(text).strip().upper()
        if not text:
            return set()

        # 统一常见分隔符
        text = text.replace("，", ",")
        text = text.replace("；", ";")
        text = text.replace("|", ",")
        text = text.replace("/", ",")
        text = text.replace("\\", ",")
        text = text.replace("\n", ",")
        text = text.replace("\t", ",")

        found = set()

        # 1. 先找标准格式
        std_matches = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text)
        found.update(std_matches)

        # 2. 再找无前缀格式
        raw_matches = re.findall(r"\b\d{4}-\d{4,7}\b", text)
        found.update({f"CVE-{m}" for m in raw_matches})

        return found

    if isinstance(value, str):
        result.update(extract_from_text(value))

    elif isinstance(value, list):
        for item in value:
            if item is None:
                continue
            result.update(extract_from_text(item))

    else:
        result.update(extract_from_text(value))

    return result


def classify_cve_consistency(cve_set, extract_set):
    """
    分类逻辑：
    - both_missing: 两边都没有
    - only_cve_id: 只有 CVE_id 有
    - only_extract_cve: 只有 extract_cve 有
    - strong_consistent: 完全一致
    - weak_consistent: 有交集但不完全一致
    - inconsistent: 两边都有，但完全无交集
    """
    if not cve_set and not extract_set:
        return "both_missing"

    if cve_set and not extract_set:
        return "only_cve_id"

    if not cve_set and extract_set:
        return "only_extract_cve"

    if cve_set == extract_set:
        return "strong_consistent"

    if cve_set & extract_set:
        return "weak_consistent"

    return "inconsistent"


def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION_NAME]

    stats = {
        "total": 0,
        "both_missing": 0,
        "only_cve_id": 0,
        "only_extract_cve": 0,
        "strong_consistent": 0,
        "weak_consistent": 0,
        "inconsistent": 0
    }

    rows = []
    bulk_ops = []

    cursor = col.find(
        {},
        {
            "_id": 1,
            "EDB_id": 1,
            "Title": 1,
            "CVE_id": 1,
            "extract_cve": 1
        },
        no_cursor_timeout=True
    )

    try:
        for doc in cursor:
            stats["total"] += 1

            raw_cve = doc.get("CVE_id")
            raw_extract = doc.get("extract_cve")

            cve_set = normalize_cve_field(raw_cve)
            extract_set = normalize_cve_field(raw_extract)

            intersection_set = cve_set & extract_set
            union_set = cve_set | extract_set

            category = classify_cve_consistency(cve_set, extract_set)
            stats[category] += 1

            cve_norm_list = sorted(cve_set)
            extract_norm_list = sorted(extract_set)
            intersection_list = sorted(intersection_set)
            union_list = sorted(union_set)

            # =========================
            # 写入 CSV 的结果
            # =========================
            rows.append({
                "_id": str(doc.get("_id")),
                "EDB_id": doc.get("EDB_id", ""),
                "Title": doc.get("Title", ""),
                "CVE_id_raw": raw_cve,
                "extract_cve_raw": raw_extract,
                "CVE_id_norm": ",".join(cve_norm_list),
                "extract_cve_norm": ",".join(extract_norm_list),
                "intersection": ",".join(intersection_list),
                "union": ",".join(union_list),
                "category": category
            })

            # =========================
            # 写回 MongoDB 的结果字段
            # =========================
            if WRITE_BACK_TO_MONGO:
                compare_result = {
                    "category": category,
                    "CVE_id_norm": cve_norm_list,
                    "extract_cve_norm": extract_norm_list,
                    "intersection": intersection_list,
                    "union": union_list,
                    "compared_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                bulk_ops.append(
                    UpdateOne(
                        {"_id": doc["_id"]},
                        {
                            "$set": {
                                "cve_compare_result": compare_result
                            }
                        }
                    )
                )

                if len(bulk_ops) >= BATCH_SIZE:
                    result = col.bulk_write(bulk_ops, ordered=False)
                    print(f"已写回 MongoDB: {result.modified_count} 条")
                    bulk_ops.clear()

        # 写入最后不足 BATCH_SIZE 的部分
        if WRITE_BACK_TO_MONGO and bulk_ops:
            result = col.bulk_write(bulk_ops, ordered=False)
            print(f"已写回 MongoDB: {result.modified_count} 条")
            bulk_ops.clear()

    finally:
        cursor.close()
        client.close()

    # =========================
    # 打印统计结果
    # =========================
    print("\n===== CVE comparison statistics =====")
    print(f"total: {stats['total']}")

    for key in [
        "both_missing",
        "only_cve_id",
        "only_extract_cve",
        "strong_consistent",
        "weak_consistent",
        "inconsistent"
    ]:
        count = stats[key]
        ratio = (count / stats["total"] * 100) if stats["total"] else 0
        print(f"{key}: {count} ({ratio:.2f}%)")

    # =========================
    # 导出 CSV
    # =========================
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_id",
                "EDB_id",
                "Title",
                "CVE_id_raw",
                "extract_cve_raw",
                "CVE_id_norm",
                "extract_cve_norm",
                "intersection",
                "union",
                "category"
            ]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDetailed results saved to: {OUTPUT_CSV}")

    if WRITE_BACK_TO_MONGO:
        print(f"Comparison results have been written back to: {DB_NAME}.{COLLECTION_NAME}")
        print("MongoDB field name: cve_compare_result")


if __name__ == "__main__":
    main()
