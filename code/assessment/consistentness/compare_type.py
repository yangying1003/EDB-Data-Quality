from pymongo import MongoClient
import csv

# =========================
# 配置区
# =========================
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "EDB_llm"
COLLECTION_NAME = "llmextract_type"   # 改成你的集合名
OUTPUT_CSV = "type_extract_type_compare.csv"


# =========================
# 工具函数
# =========================
def normalize_type_field(value):
    """
    将 Type / extract_type 统一转成 set[str]
    支持:
    - None
    - "remote"
    - "remote, webapps"
    - ["remote", "webapps"]
    """
    if value is None:
        return set()

    # 如果是字符串
    if isinstance(value, str):
        value = value.strip().lower()
        if not value:
            return set()

        # 兼容 "remote, webapps" / "remote/webapps" / "remote|webapps"
        for sep in ["/", "|", ";"]:
            value = value.replace(sep, ",")

        parts = [x.strip() for x in value.split(",") if x.strip()]
        return set(parts)

    # 如果是列表
    if isinstance(value, list):
        result = set()
        for item in value:
            if isinstance(item, str):
                item = item.strip().lower()
                if not item:
                    continue

                for sep in ["/", "|", ";"]:
                    item = item.replace(sep, ",")

                parts = [x.strip() for x in item.split(",") if x.strip()]
                result.update(parts)
        return result

    return set()


def classify_type_consistency(type_set, extract_set):
    """
    按论文思路分类：
    - missing
    - consistent
    - under_covered
    - inconsistent
    - partial_overlap
    """
    if not type_set or not extract_set:
        return "missing"

    if type_set == extract_set:
        return "consistent"

    # 结构化字段覆盖不足：Type 只是 extract_type 的一部分
    if type_set < extract_set:
        return "under_covered"

    # 完全无交集
    if type_set.isdisjoint(extract_set):
        return "inconsistent"

    # 有部分交集，但不是完全一致，也不是单纯覆盖不足
    return "partial_overlap"


# =========================
# 主程序
# =========================
def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION_NAME]

    stats = {
        "total": 0,
        "missing": 0,
        "consistent": 0,
        "under_covered": 0,
        "inconsistent": 0,
        "partial_overlap": 0
    }

    rows = []

    cursor = col.find(
        {},
        {
            "_id": 1,
            "EDB_id": 1,
            "Title": 1,
            "Type": 1,
            "extract_type": 1
        }
    )

    for doc in cursor:
        stats["total"] += 1

        raw_type = doc.get("Type")
        raw_extract = doc.get("extract_type")

        type_set = normalize_type_field(raw_type)
        extract_set = normalize_type_field(raw_extract)

        category = classify_type_consistency(type_set, extract_set)
        stats[category] += 1

        rows.append({
            "_id": str(doc.get("_id")),
            "EDB_id": doc.get("EDB_id", ""),
            "Title": doc.get("Title", ""),
            "Type_raw": raw_type,
            "extract_type_raw": raw_extract,
            "Type_norm": ",".join(sorted(type_set)),
            "extract_type_norm": ",".join(sorted(extract_set)),
            "category": category
        })

    # 输出统计
    print("\n===== 比较结果统计 =====")
    print(f"总数: {stats['total']}")
    for key in ["missing", "consistent", "under_covered", "inconsistent", "partial_overlap"]:
        count = stats[key]
        ratio = (count / stats["total"] * 100) if stats["total"] else 0
        print(f"{key}: {count} ({ratio:.2f}%)")

    # 导出 CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_id", "EDB_id", "Title",
                "Type_raw", "extract_type_raw",
                "Type_norm", "extract_type_norm",
                "category"
            ]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n详细结果已导出到: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
