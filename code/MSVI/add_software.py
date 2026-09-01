from pymongo import MongoClient

# =========================================================
# 1. MongoDB 连接配置
# =========================================================
MONGO_URI = "mongodb://localhost:27017"
#
# DB_NAME = "EDB_completeness"
# COLLECTION_NAME = "Multiple_Software"
DB_NAME = "Vertify_complete"
COLLECTION_NAME = "collection_repairverify"
# 新写入字段
OUTPUT_FIELD = "add_softwares"

# 补全后的标头
HEADER = "# Software Link:"


# =========================================================
# 2. 字段与来源名称对应关系
# =========================================================
SOFTWARE_FIELDS = [
    ("cnnvds_softwares", "CNNVD"),
    ("cves_softwares", "CVE"),
    ("nvds_softwares", "NVD"),
    ("EDBs_softwares", "EDB"),
]


# =========================================================
# 3. 判断字段是否为空
# =========================================================
def is_empty(value):
    """
    判断字段值是否为空。
    支持 None、空字符串、空列表、空字典等情况。
    """
    if value is None:
        return True

    if isinstance(value, str):
        text = value.strip()
        return text == "" or text.lower() in {"none", "null", "[]", "{}"}

    if isinstance(value, (list, tuple, set)):
        return len(value) == 0

    if isinstance(value, dict):
        return len(value) == 0

    return False


# =========================================================
# 4. 将字段值统一转换为 list[str]
# =========================================================
def normalize_to_list(value):
    """
    将不同格式的软件字段统一转换成 list[str]。

    支持：
    1. ["A", "B", "C"]
    2. "A"
    3. "A, B, C"
    4. {"softwares": ["A", "B", "C"]}
    """

    if is_empty(value):
        return []

    result = []

    # 情况1：列表、元组、集合
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if not is_empty(item):
                result.append(str(item).strip())

    # 情况2：字典
    elif isinstance(value, dict):
        for _, v in value.items():
            if isinstance(v, (list, tuple, set)):
                for item in v:
                    if not is_empty(item):
                        result.append(str(item).strip())
            elif not is_empty(v):
                result.append(str(v).strip())

    # 情况3：字符串
    elif isinstance(value, str):
        text = value.strip()

        # 如果字符串里本身包含逗号，则拆分
        if "," in text:
            parts = text.split(",")
            for part in parts:
                part = part.strip()
                if part:
                    result.append(part)
        else:
            result.append(text)

    # 情况4：其他类型，例如数字
    else:
        result.append(str(value).strip())

    # 去重，但保持原始顺序
    seen = set()
    deduped = []

    for item in result:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped


# =========================================================
# 5. 生成 add_softwares 字段内容
# =========================================================
def build_add_softwares(doc):
    """
    根据四个软件来源字段生成 add_softwares。

    例如：
    cnnvds_softwares = ["A", "B", "C"]
    cves_softwares = ["D"]

    生成：
    # Software Link: A,B,C(from CNNVD); D(from CVE)
    """

    parts = []

    for field_name, source_name in SOFTWARE_FIELDS:
        raw_value = doc.get(field_name)

        softwares = normalize_to_list(raw_value)

        if softwares:
            software_text = ",".join(softwares)
            parts.append(f"{software_text}(from {source_name})")

    if not parts:
        return ""

    return HEADER + " " + "; ".join(parts)


# =========================================================
# 6. 主程序
# =========================================================
def main():
    client = MongoClient(MONGO_URI)
    collection = client[DB_NAME][COLLECTION_NAME]

    total_count = collection.count_documents({})

    updated_count = 0
    empty_count = 0

    cursor = collection.find(
        {},
        {
            "EDB_id": 1,
            "cnnvds_softwares": 1,
            "cves_softwares": 1,
            "nvds_softwares": 1,
            "EDBs_softwares": 1,
        }
    )

    print("=" * 90)
    print("开始生成 add_softwares 字段")
    print(f"数据库: {DB_NAME}")
    print(f"集合: {COLLECTION_NAME}")
    print(f"总文档数: {total_count}")
    print(f"写入字段: {OUTPUT_FIELD}")
    print("=" * 90)

    for doc in cursor:
        doc_id = doc["_id"]
        edb_id = doc.get("EDB_id", "")

        add_softwares = build_add_softwares(doc)

        if add_softwares == "":
            empty_count += 1

        collection.update_one(
            {"_id": doc_id},
            {
                "$set": {
                    OUTPUT_FIELD: add_softwares
                }
            }
        )

        updated_count += 1

        print(
            f"[{updated_count}/{total_count}] "
            f"EDB_id={edb_id} -> {add_softwares}"
        )

    print("=" * 90)
    print("处理完成")
    print(f"总文档数: {total_count}")
    print(f"已更新文档数: {updated_count}")
    print(f"add_softwares 为空的文档数: {empty_count}")
    print(f"add_softwares 不为空的文档数: {updated_count - empty_count}")
    print("=" * 90)

    client.close()


if __name__ == "__main__":
    main()