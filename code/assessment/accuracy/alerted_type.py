# -*- coding: utf-8 -*-
"""
统计 EDB_imporve.EDB_type_improve 中 Type 字段修正了多少个 EDB 报告。

重点统计：
1. 总共写入多少条修正建议；
2. 真正需要修正的文档数；
3. 真正需要修正的 EDB 报告数，按 edb_id 去重；
4. edb_s_type 修正了多少个报告；
5. edb_us_type 修正了多少个报告；
6. 新增 / 删除 Type 标签的数量。
"""

from pymongo import MongoClient
from collections import Counter

MONGO_URI = "mongodb://localhost:27017/"

DB_NAME = "EDB_imporve"
COLLECTION_NAME = "EDB_type_improve"

client = MongoClient(MONGO_URI)
col = client[DB_NAME][COLLECTION_NAME]


def non_empty_array(field_name):
    """
    MongoDB 查询条件：数组字段存在且非空
    """
    return {
        field_name: {
            "$exists": True,
            "$type": "array",
            "$ne": []
        }
    }


def count_distinct_edb_id(query):
    return len(col.distinct("edb_id", query))


def main():
    total_docs = col.count_documents({})

    replace_docs = col.count_documents({
        "repair_action": "replace_or_update"
    })

    replace_reports = count_distinct_edb_id({
        "repair_action": "replace_or_update"
    })

    manual_review_docs = col.count_documents({
        "repair_action": "manual_review"
    })

    manual_review_reports = count_distinct_edb_id({
        "repair_action": "manual_review"
    })

    no_change_docs = col.count_documents({
        "repair_action": "no_change"
    })

    no_change_reports = count_distinct_edb_id({
        "repair_action": "no_change"
    })

    # edb_s_type 发生修正：新增或删除不为空
    edb_s_changed_query = {
        "repair_action": "replace_or_update",
        "$or": [
            non_empty_array("edb_s_add_types"),
            non_empty_array("edb_s_remove_types")
        ]
    }

    # edb_us_type 发生修正：新增或删除不为空
    edb_us_changed_query = {
        "repair_action": "replace_or_update",
        "$or": [
            non_empty_array("edb_us_add_types"),
            non_empty_array("edb_us_remove_types")
        ]
    }

    edb_s_changed_docs = col.count_documents(edb_s_changed_query)
    edb_s_changed_reports = count_distinct_edb_id(edb_s_changed_query)

    edb_us_changed_docs = col.count_documents(edb_us_changed_query)
    edb_us_changed_reports = count_distinct_edb_id(edb_us_changed_query)

    # 只新增、只删除、既新增又删除
    edb_s_add_query = {
        "repair_action": "replace_or_update",
        **non_empty_array("edb_s_add_types")
    }

    edb_s_remove_query = {
        "repair_action": "replace_or_update",
        **non_empty_array("edb_s_remove_types")
    }

    edb_us_add_query = {
        "repair_action": "replace_or_update",
        **non_empty_array("edb_us_add_types")
    }

    edb_us_remove_query = {
        "repair_action": "replace_or_update",
        **non_empty_array("edb_us_remove_types")
    }

    edb_s_add_reports = count_distinct_edb_id(edb_s_add_query)
    edb_s_remove_reports = count_distinct_edb_id(edb_s_remove_query)

    edb_us_add_reports = count_distinct_edb_id(edb_us_add_query)
    edb_us_remove_reports = count_distinct_edb_id(edb_us_remove_query)

    # 统计具体新增/删除了哪些 Type 标签
    add_remove_counter = {
        "edb_s_add_types": Counter(),
        "edb_s_remove_types": Counter(),
        "edb_us_add_types": Counter(),
        "edb_us_remove_types": Counter(),
        "true_type": Counter(),
    }

    cursor = col.find(
        {"repair_action": "replace_or_update"},
        {
            "_id": 0,
            "edb_s_add_types": 1,
            "edb_s_remove_types": 1,
            "edb_us_add_types": 1,
            "edb_us_remove_types": 1,
            "true_type": 1,
        }
    )

    for doc in cursor:
        for field in add_remove_counter.keys():
            values = doc.get(field, [])
            if isinstance(values, list):
                add_remove_counter[field].update(values)

    # 按告警等级统计
    red_docs = col.count_documents({
        "repair_action": "replace_or_update",
        "max_alert_level": "red"
    })

    red_reports = count_distinct_edb_id({
        "repair_action": "replace_or_update",
        "max_alert_level": "red"
    })

    orange_docs = col.count_documents({
        "repair_action": "replace_or_update",
        "max_alert_level": "orange"
    })

    orange_reports = count_distinct_edb_id({
        "repair_action": "replace_or_update",
        "max_alert_level": "orange"
    })

    print("=" * 70)
    print("Type 字段修正统计")
    print("=" * 70)

    print(f"修正建议集合: {DB_NAME}.{COLLECTION_NAME}")
    print(f"总写入文档数: {total_docs}")
    print()

    print("[1] 按 repair_action 统计")
    print(f"真正需要修正的文档数 replace_or_update: {replace_docs}")
    print(f"真正需要修正的 EDB 报告数，按 edb_id 去重: {replace_reports}")
    print(f"需要人工复核的文档数 manual_review: {manual_review_docs}")
    print(f"需要人工复核的 EDB 报告数: {manual_review_reports}")
    print(f"无需修改的文档数 no_change: {no_change_docs}")
    print(f"无需修改的 EDB 报告数: {no_change_reports}")
    print()

    print("[2] EDB 结构化字段 edb_s_type 修正情况")
    print(f"edb_s_type 发生修正的文档数: {edb_s_changed_docs}")
    print(f"edb_s_type 发生修正的 EDB 报告数: {edb_s_changed_reports}")
    print(f"edb_s_type 需要新增标签的 EDB 报告数: {edb_s_add_reports}")
    print(f"edb_s_type 需要删除标签的 EDB 报告数: {edb_s_remove_reports}")
    print()

    print("[3] EDB 非结构化抽取字段 edb_us_type 修正情况")
    print(f"edb_us_type 发生修正的文档数: {edb_us_changed_docs}")
    print(f"edb_us_type 发生修正的 EDB 报告数: {edb_us_changed_reports}")
    print(f"edb_us_type 需要新增标签的 EDB 报告数: {edb_us_add_reports}")
    print(f"edb_us_type 需要删除标签的 EDB 报告数: {edb_us_remove_reports}")
    print()

    print("[4] 按告警等级统计真正修正的报告")
    print(f"红色告警中真正修正的文档数: {red_docs}")
    print(f"红色告警中真正修正的 EDB 报告数: {red_reports}")
    print(f"橙色告警中真正修正的文档数: {orange_docs}")
    print(f"橙色告警中真正修正的 EDB 报告数: {orange_reports}")
    print()

    print("[5] 具体 Type 标签修正分布")
    for field, counter in add_remove_counter.items():
        print(f"\n{field}:")
        if not counter:
            print("  无")
        else:
            for label, count in counter.most_common():
                print(f"  {label}: {count}")

    # 写入 txt
    output_path = "type_repair_report_count_summary.txt"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("Type 字段修正统计\n")
        f.write("=" * 70 + "\n")
        f.write(f"修正建议集合: {DB_NAME}.{COLLECTION_NAME}\n")
        f.write(f"总写入文档数: {total_docs}\n\n")

        f.write("[1] 按 repair_action 统计\n")
        f.write(f"真正需要修正的文档数 replace_or_update: {replace_docs}\n")
        f.write(f"真正需要修正的 EDB 报告数，按 edb_id 去重: {replace_reports}\n")
        f.write(f"需要人工复核的文档数 manual_review: {manual_review_docs}\n")
        f.write(f"需要人工复核的 EDB 报告数: {manual_review_reports}\n")
        f.write(f"无需修改的文档数 no_change: {no_change_docs}\n")
        f.write(f"无需修改的 EDB 报告数: {no_change_reports}\n\n")

        f.write("[2] EDB 结构化字段 edb_s_type 修正情况\n")
        f.write(f"edb_s_type 发生修正的文档数: {edb_s_changed_docs}\n")
        f.write(f"edb_s_type 发生修正的 EDB 报告数: {edb_s_changed_reports}\n")
        f.write(f"edb_s_type 需要新增标签的 EDB 报告数: {edb_s_add_reports}\n")
        f.write(f"edb_s_type 需要删除标签的 EDB 报告数: {edb_s_remove_reports}\n\n")

        f.write("[3] EDB 非结构化抽取字段 edb_us_type 修正情况\n")
        f.write(f"edb_us_type 发生修正的文档数: {edb_us_changed_docs}\n")
        f.write(f"edb_us_type 发生修正的 EDB 报告数: {edb_us_changed_reports}\n")
        f.write(f"edb_us_type 需要新增标签的 EDB 报告数: {edb_us_add_reports}\n")
        f.write(f"edb_us_type 需要删除标签的 EDB 报告数: {edb_us_remove_reports}\n\n")

        f.write("[4] 按告警等级统计真正修正的报告\n")
        f.write(f"红色告警中真正修正的文档数: {red_docs}\n")
        f.write(f"红色告警中真正修正的 EDB 报告数: {red_reports}\n")
        f.write(f"橙色告警中真正修正的文档数: {orange_docs}\n")
        f.write(f"橙色告警中真正修正的 EDB 报告数: {orange_reports}\n\n")

        f.write("[5] 具体 Type 标签修正分布\n")
        for field, counter in add_remove_counter.items():
            f.write(f"\n{field}:\n")
            if not counter:
                f.write("  无\n")
            else:
                for label, count in counter.most_common():
                    f.write(f"  {label}: {count}\n")

    print()
    print(f"[DONE] 统计结果已写入: {output_path}")


if __name__ == "__main__":
    main()