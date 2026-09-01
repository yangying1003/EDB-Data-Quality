from pymongo import MongoClient

# =========================================================
# 1. MongoDB 连接配置
# =========================================================
MONGO_URI = "mongodb://localhost:27017"

# DB_NAME = "EDB_completeness"
# COLLECTION_NAME = "Multiple_Testedon"
DB_NAME = "Vertify_complete"
COLLECTION_NAME = "collection_repairverify"

# 新写入字段
OUTPUT_FIELD = "add_testedon"

# 补全后的标头格式
HEADER = "#Tested on:"


# =========================================================
# 2. 字段与来源名称对应关系
# =========================================================
PLATFORM_FIELDS = [
    ("platform_cnnvds", "CNNVD"),
    ("platform_cves", "CVE"),
    ("platform_nvds", "NVD"),
    ("platform_edbs_us", "Exploit_DB_us"),
    ("platform_edbs_s", "Exploit_DB_s"),
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
    将不同格式的平台字段统一转换成 list[str]。

    支持：
    1. ["Windows", "Linux"]
    2. "Windows"
    3. "Windows, Linux"
    4. {"platform": ["Windows", "Linux"]}
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

        # 如果字符串中包含逗号，则拆分
        if "," in text:
            parts = text.split(",")
            for part in parts:
                part = part.strip()
                if part:
                    result.append(part)
        else:
            result.append(text)

    # 情况4：其他类型
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
# 5. 根据 platform_repair 生成 add_testedon
# =========================================================
def build_from_repair(doc):
    """
    如果 platform_repair 不为空，优先使用 platform_repair。
    """

    repair_value = doc.get("platform_repair")
    repair_platforms = normalize_to_list(repair_value)

    if not repair_platforms:
        return ""

    platform_text = ",".join(repair_platforms)

    return f"{HEADER} {platform_text}(from CNNVD,CVE,NVD,EDB)"


# =========================================================
# 6. 根据多个来源字段生成 add_testedon
# =========================================================
def build_from_sources(doc):
    """
    如果 platform_repair 为空，则根据多个来源字段生成 add_testedon。
    """

    parts = []

    for field_name, source_name in PLATFORM_FIELDS:
        raw_value = doc.get(field_name)

        platforms = normalize_to_list(raw_value)

        if platforms:
            platform_text = ",".join(platforms)
            parts.append(f"{platform_text}(from {source_name})")

    if not parts:
        return ""

    return HEADER + " " + "; ".join(parts)


# =========================================================
# 7. 生成最终 add_testedon 字段
# =========================================================
def build_add_testedon(doc):
    """
    生成 add_testedon 字段。

    规则：
    1. platform_repair 不为空：优先使用 platform_repair；
    2. platform_repair 为空：再使用 CNNVD、CVE、NVD、EDB_us、EDB_s。
    """

    # 第一优先级：platform_repair
    add_testedon = build_from_repair(doc)

    if add_testedon:
        return add_testedon

    # 第二优先级：多个来源字段
    return build_from_sources(doc)


# =========================================================
# 8. 主程序
# =========================================================
def main():
    client = MongoClient(MONGO_URI)
    collection = client[DB_NAME][COLLECTION_NAME]

    total_count = collection.count_documents({})

    updated_count = 0
    repair_used_count = 0
    sources_used_count = 0
    empty_count = 0

    cursor = collection.find(
        {},
        {
            "EDB_id": 1,
            "platform_cnnvds": 1,
            "platform_cves": 1,
            "platform_edbs_s": 1,
            "platform_edbs_us": 1,
            "platform_nvds": 1,
            "platform_repair": 1,
        }
    )

    print("=" * 90)
    print("开始生成 add_testedon 字段")
    print(f"数据库: {DB_NAME}")
    print(f"集合: {COLLECTION_NAME}")
    print(f"总文档数: {total_count}")
    print(f"写入字段: {OUTPUT_FIELD}")
    print("=" * 90)

    for doc in cursor:
        doc_id = doc["_id"]
        edb_id = doc.get("EDB_id", "")

        add_testedon = build_add_testedon(doc)

        # 统计来源类型
        if add_testedon == "":
            empty_count += 1
            source_type = "empty"
        elif normalize_to_list(doc.get("platform_repair")):
            repair_used_count += 1
            source_type = "platform_repair"
        else:
            sources_used_count += 1
            source_type = "multi_sources"

        collection.update_one(
            {"_id": doc_id},
            {
                "$set": {
                    OUTPUT_FIELD: add_testedon
                }
            }
        )

        updated_count += 1

        print(
            f"[{updated_count}/{total_count}] "
            f"EDB_id={edb_id} | source={source_type} -> {add_testedon}"
        )

    print("=" * 90)
    print("处理完成")
    print(f"总文档数: {total_count}")
    print(f"已更新文档数: {updated_count}")
    print(f"使用 platform_repair 生成的文档数: {repair_used_count}")
    print(f"使用多个来源字段生成的文档数: {sources_used_count}")
    print(f"add_testedon 为空的文档数: {empty_count}")
    print(f"add_testedon 不为空的文档数: {updated_count - empty_count}")
    print("=" * 90)

    client.close()


if __name__ == "__main__":
    main()