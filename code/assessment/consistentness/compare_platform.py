from pymongo import MongoClient
import csv

# =========================
# 配置区
# =========================
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "EDB_llm"
COLLECTION_NAME = "llmextract_platform"
OUTPUT_CSV = "platform_extract_platform_compare.csv"


# =========================
# 工具函数
# =========================
def normalize_platform_field(value):
    """
    将 Platform / extract_platform 统一转成 set[str]
    支持：
    - None
    - "windows"
    - "Windows"
    - "windows, linux"
    - ["windows", "linux"]
    """
    if value is None:
        return set()

    result = set()

    def split_text(text):
        text = str(text).strip().lower()
        if not text:
            return set()

        # 统一常见分隔符
        for sep in ["|", "/", ";", "；", "，", "\\", "\n", "\t"]:
            text = text.replace(sep, ",")

        parts = [x.strip() for x in text.split(",") if x.strip()]
        return set(parts)

    if isinstance(value, str):
        result.update(split_text(value))
    elif isinstance(value, list):
        for item in value:
            if item is None:
                continue
            result.update(split_text(item))
    else:
        result.update(split_text(value))

    return result


def classify_platform_consistency(raw_platform, platform_set, extract_set):
    """
    分类逻辑：
    1. Platform = Multiple 时特殊处理：
       - extract_set 为空 -> missing
       - len(extract_set) >= 2 -> consistent
       - len(extract_set) < 2 -> inconsistent

    2. 其他平台按普通集合关系：
       - missing
       - consistent
       - under_covered
       - inconsistent
       - partial_overlap
    """
    raw_platform_str = ""
    if raw_platform is not None:
        raw_platform_str = str(raw_platform).strip().lower()

    # ===== 特殊规则：Multiple =====
    if raw_platform_str == "multiple":
        if not extract_set:
            return "missing"
        elif len(extract_set) >= 2:
            return "consistent"
        else:
            return "inconsistent"

    # ===== 普通规则 =====
    if not platform_set or not extract_set:
        return "missing"

    if platform_set == extract_set:
        return "consistent"

    if platform_set < extract_set:
        return "under_covered"

    if platform_set.isdisjoint(extract_set):
        return "inconsistent"

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
            "Platform": 1,
            "extract_platform": 1
        }
    )

    for doc in cursor:
        stats["total"] += 1

        raw_platform = doc.get("Platform")
        raw_extract = doc.get("extract_platform")

        platform_set = normalize_platform_field(raw_platform)
        extract_set = normalize_platform_field(raw_extract)

        category = classify_platform_consistency(
            raw_platform=raw_platform,
            platform_set=platform_set,
            extract_set=extract_set
        )
        stats[category] += 1

        rows.append({
            "_id": str(doc.get("_id")),
            "EDB_id": doc.get("EDB_id", ""),
            "Title": doc.get("Title", ""),
            "Platform_raw": raw_platform,
            "extract_platform_raw": raw_extract,
            "Platform_norm": ",".join(sorted(platform_set)),
            "extract_platform_norm": ",".join(sorted(extract_set)),
            "extract_platform_count": len(extract_set),
            "category": category
        })

    # 输出统计
    print("\n===== Platform comparison statistics =====")
    print(f"total: {stats['total']}")
    for key in ["missing", "consistent", "under_covered", "inconsistent", "partial_overlap"]:
        count = stats[key]
        ratio = (count / stats["total"] * 100) if stats["total"] else 0
        print(f"{key}: {count} ({ratio:.2f}%)")

    # 导出 CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "_id",
                "EDB_id",
                "Title",
                "Platform_raw",
                "extract_platform_raw",
                "Platform_norm",
                "extract_platform_norm",
                "extract_platform_count",
                "category"
            ]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDetailed results saved to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
