from pymongo import MongoClient

# 连接 MongoDB
client = MongoClient("mongodb://localhost:27017/")

# 数据库和集合
db = client["EDB_completeness"]
collection = db["Multiple_Date"]
# 统计信息
total_count = 0
updated_count = 0
missing_Date_count = 0

# 遍历集合中的所有文档
for doc in collection.find({}, {"Date": 1}):
    total_count += 1

    # 读取 Date 字段
    Date = doc.get("Date")

    # 如果 Date 字段不存在或为空，则跳过
    if Date is None or str(Date).strip() == "":
        missing_Date_count += 1
        continue

    # 构造 add_Date 字段内容
    add_Date_value = f"# Exploit Date: {str(Date).strip()}"

    # 写入 add_Date 字段
    result = collection.update_one(
        {"_id": doc["_id"]},
        {
            "$set": {
                "add_Date": add_Date_value
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
print(f"成功写入 add_Date 字段的文档数: {updated_count}")
print(f"Date 缺失或为空的文档数: {missing_Date_count}")