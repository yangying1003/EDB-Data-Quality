from pymongo import MongoClient

# 连接 MongoDB
client = MongoClient("mongodb://localhost:27017/")

# 数据库和集合
db = client["EDB_completeness"]
collection = db["Multiple_Title"]
# TARGET_DB = "Vertify_complete"
# TARGET_COL = "collection_repairverify"
# 统计信息
total_count = 0
updated_count = 0
missing_title_count = 0

# 遍历集合中的所有文档，只读取 Title 字段
for doc in collection.find({}, {"Title": 1}):
    total_count += 1

    # 读取 Title 字段
    title = doc.get("Title")

    # 如果 Title 字段不存在或为空，则跳过
    if title is None or str(title).strip() == "":
        missing_title_count += 1
        continue

    # 构造 add_title 字段内容
    add_title_value = f"# Exploit Title: {str(title).strip()}"

    # 写入 add_title 字段
    result = collection.update_one(
        {"_id": doc["_id"]},
        {
            "$set": {
                "add_title": add_title_value
            }
        }
    )

    if result.modified_count > 0:
        updated_count += 1

# 输出统计结果
print("=" * 60)
print("处理完成")
print("=" * 60)
print(f"集合总文档数: {total_count}")
print(f"成功写入 add_title 字段的文档数: {updated_count}")
print(f"Title 缺失或为空的文档数: {missing_title_count}")