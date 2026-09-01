# -*- coding: utf-8 -*-

from pymongo import MongoClient, ReplaceOne
from collections import defaultdict

MONGO_URI = "mongodb://localhost:27017/"

DB_NAME = "EDB_imporve"

SOURCE_COLLECTION = "EDB_platform_report_repair_support2"
OUTPUT_COLLECTION = "EDB_platform_repair_merge_simple"

BATCH_SIZE = 1000

client = MongoClient(MONGO_URI)

src_col = client[DB_NAME][SOURCE_COLLECTION]
out_col = client[DB_NAME][OUTPUT_COLLECTION]

out_col.drop()


def to_list(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]

    if isinstance(value, set):
        return [str(x).strip() for x in value if str(x).strip()]

    if isinstance(value, tuple):
        return [str(x).strip() for x in value if str(x).strip()]

    value = str(value).strip()
    if not value:
        return []

    return [value]


merged = defaultdict(lambda: {
    "CVE_id": set(),
    "EDB_us_platform": set(),
    "EDB_s_platform": set(),
    "repair_platform": set()
})

cursor = src_col.find(
    {},
    {
        "edb_id": 1,
        "CVE-ID": 1,
        "original_EDB_us_platform": 1,
        "original_EDB_s_platform": 1,
        "repair_platform": 1
    },
    no_cursor_timeout=True
)

try:
    for doc in cursor:
        edb_id = doc.get("edb_id")

        if edb_id is None:
            continue

        edb_id = str(edb_id).strip()

        if not edb_id or edb_id == "NO_EDB":
            continue

        for cve in to_list(doc.get("CVE-ID")):
            if cve and cve != "NO_CVE":
                merged[edb_id]["CVE_id"].add(cve)

        for p in to_list(doc.get("original_EDB_us_platform")):
            merged[edb_id]["EDB_us_platform"].add(p)

        for p in to_list(doc.get("original_EDB_s_platform")):
            merged[edb_id]["EDB_s_platform"].add(p)

        for p in to_list(doc.get("repair_platform")):
            merged[edb_id]["repair_platform"].add(p)

finally:
    cursor.close()


ops = []

for edb_id, item in merged.items():
    new_doc = {
        "_id": edb_id,
        "EDB_id": edb_id,
        "CVE_id": sorted(item["CVE_id"]),
        "EDB_us_platform": sorted(item["EDB_us_platform"]),
        "EDB_s_platform": sorted(item["EDB_s_platform"]),
        "repair_platform": sorted(item["repair_platform"])
    }

    ops.append(
        ReplaceOne(
            {"_id": edb_id},
            new_doc,
            upsert=True
        )
    )

    if len(ops) >= BATCH_SIZE:
        out_col.bulk_write(ops, ordered=False)
        ops.clear()

if ops:
    out_col.bulk_write(ops, ordered=False)

out_col.create_index("EDB_id", unique=True)
out_col.create_index("CVE_id")
out_col.create_index("repair_platform")

print("完成")
print(f"来源集合: {DB_NAME}.{SOURCE_COLLECTION}")
print(f"输出集合: {DB_NAME}.{OUTPUT_COLLECTION}")
print(f"融合后的 EDB_id 数量: {out_col.count_documents({})}")