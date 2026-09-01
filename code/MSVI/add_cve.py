from pymongo import MongoClient, UpdateMany
from collections import defaultdict
from pathlib import Path


# =========================
# 1. MongoDB 连接配置
# =========================
MONGO_URI = "mongodb://localhost:27017/"

SOURCE_DB = "EDB_llm"
SOURCE_COL = "llmextract_cve"

TARGET_DB = "EDB_completeness"
TARGET_COL = "Multiple_CVE"

UNMATCHED_OUTPUT_FILE = Path(
    r"unmatched_add_cve_edb_id.txt"
)


# =========================
# 2. 基础函数
# =========================
def normalize_edb_id(value):
    """
    统一 EDB_id 的比较形式。
    例如 123 和 "123" 都统一成 "123"。
    """
    if value is None:
        return None
    return str(value).strip()


def normalize_cve_array(value):
    """
    确保 new_cve 被写入时一定是数组类型。
    """
    if value is None:
        return []

    if isinstance(value, list):
        result = []
        for item in value:
            if item is None:
                continue
            item = str(item).strip()
            if item:
                result.append(item)
        return list(dict.fromkeys(result))

    value = str(value).strip()
    if not value:
        return []

    return [value]


def build_edb_id_query(edb_id_str):
    """
    构造 EDB_id 查询条件，兼容目标集合中 EDB_id 是字符串或数字的情况。
    """
    values = [edb_id_str]

    if edb_id_str.isdigit():
        values.append(int(edb_id_str))

    return {"EDB_id": {"$in": values}}


# =========================
# 3. 主程序
# =========================
def main():
    client = MongoClient(MONGO_URI)

    source_col = client[SOURCE_DB][SOURCE_COL]
    target_col = client[TARGET_DB][TARGET_COL]

    # 读取目标集合中已有的 EDB_id，方便统计哪些源数据没有匹配到目标文档
    target_edb_ids = set()

    for doc in target_col.find({}, {"EDB_id": 1}):
        edb_id = normalize_edb_id(doc.get("EDB_id"))
        if edb_id:
            target_edb_ids.add(edb_id)

    # 从源集合读取 EDB_id 和 new_cve
    # 如果同一个 EDB_id 在源集合中出现多次，则合并它们的 new_cve
    source_map = defaultdict(list)

    total_source_docs = 0
    skipped_no_edb_id = 0

    cursor = source_col.find(
        {"new_cve": {"$exists": True}},
        {"EDB_id": 1, "new_cve": 1}
    )

    for doc in cursor:
        total_source_docs += 1

        edb_id = normalize_edb_id(doc.get("EDB_id"))
        if not edb_id:
            skipped_no_edb_id += 1
            continue

        cve_list = normalize_cve_array(doc.get("new_cve"))
        source_map[edb_id].extend(cve_list)

    # 对每个 EDB_id 下的 CVE 数组去重
    for edb_id in source_map:
        source_map[edb_id] = list(dict.fromkeys(source_map[edb_id]))

    # 生成批量更新操作
    operations = []
    unmatched_ids = []

    for edb_id, cve_list in source_map.items():
        if edb_id not in target_edb_ids:
            unmatched_ids.append(edb_id)
            continue

        operations.append(
            UpdateMany(
                build_edb_id_query(edb_id),
                {
                    "$set": {
                        "add_cve": cve_list
                    }
                }
            )
        )

    # 批量写入目标集合
    matched_count = 0
    modified_count = 0

    if operations:
        result = target_col.bulk_write(operations, ordered=False)
        matched_count = result.matched_count
        modified_count = result.modified_count

    # 导出未匹配到的 EDB_id
    UNMATCHED_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(UNMATCHED_OUTPUT_FILE, "w", encoding="utf-8") as f:
        for edb_id in sorted(unmatched_ids, key=lambda x: int(x) if x.isdigit() else x):
            f.write(f"{edb_id}\n")

    # 输出运行摘要
    print("=" * 80)
    print("new_cve 写入 add_cve 完成")
    print("=" * 80)
    print(f"源集合: {SOURCE_DB}.{SOURCE_COL}")
    print(f"目标集合: {TARGET_DB}.{TARGET_COL}")
    print("-" * 80)
    print(f"源集合中存在 new_cve 字段的文档数: {total_source_docs}")
    print(f"源集合中缺少 EDB_id 的文档数: {skipped_no_edb_id}")
    print(f"源集合中不同 EDB_id 数量: {len(source_map)}")
    print(f"成功生成更新操作的 EDB_id 数量: {len(operations)}")
    print(f"目标集合中匹配到的文档数: {matched_count}")
    print(f"实际被修改的文档数: {modified_count}")
    print(f"未在目标集合中匹配到的 EDB_id 数量: {len(unmatched_ids)}")
    print(f"未匹配 EDB_id 已导出到: {UNMATCHED_OUTPUT_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    main()