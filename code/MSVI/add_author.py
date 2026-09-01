from pymongo import MongoClient

# 连接 MongoDB
client = MongoClient("mongodb://localhost:27017/")

# 数据库和集合
db = client["EDB_completeness"]
collection = db["Multiple_Author"]

# 统计信息
total_count = 0
updated_count = 0
missing_author_count = 0

# 遍历集合中的所有文档
for doc in collection.find({}, {"Author": 1}):
    total_count += 1

    # 读取 Author 字段
    author = doc.get("Author")

    # 如果 Author 字段不存在或为空，则跳过
    if author is None or str(author).strip() == "":
        missing_author_count += 1
        continue

    # 构造 add_author 字段内容
    add_author_value = f"# Exploit Author: {str(author).strip()}"

    # 写入 add_author 字段
    result = collection.update_one(
        {"_id": doc["_id"]},
        {
            "$set": {
                "add_author": add_author_value
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
print(f"成功写入 add_author 字段的文档数: {updated_count}")
print(f"Author 缺失或为空的文档数: {missing_author_count}")