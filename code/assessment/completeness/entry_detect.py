#!/usr/bin/env python3
# coding: utf-8
"""
检测 MongoDB 中 EDB 集合内 POC 字段的报告完整性

功能：
1. 检测 9 个 EDB 官方建议标头是否存在；
2. 支持标准写法和多种变体写法；
3. 支持倒装写法，例如：
   # Link Software:
   # Author Exploit:
4. 支持扩展写法，例如：
   # Tested on OS:
   # Exploit Date:
   # Vendor URL:
5. 支持不同分隔符：
   :  ：  =  -  –  —
6. 保留规则：
   只要匹配到标头，就认为该标头存在；
   即使值是 N/A、None、Unknown、Not Available、- 等，也算存在；
   但这些空值型表达会额外记录到 empty_matched_lines。
7. 新增支持：
   Found by:
   Discovered By:
   Discoverd By:
   Discovered On:
   #[+] Dork:
   : # Software:
   : # Date:
   : # Author:
   [*] Discovered By:
   [+] Discovered On:
8. 支持写回 MongoDB；
9. 导出统计 JSON 和缺失明细 JSON。
"""

import re
import json
from collections import defaultdict
from pymongo import MongoClient

try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda x, **kwargs: x


# ============================================================
# 一、基础配置
# ============================================================

MONGO_URI = "mongodb://localhost:27017"

DB_NAME = "EDB"
COLLECTION_NAME = "edb_data_deletenull"

POC_FIELD = "POC"
EDB_ID_FIELD = "EDB_id"

# 是否写回 MongoDB
WRITE_BACK = True

# 只处理部分数据时设置为整数；处理全部则设为 None
LIMIT = None

# 是否只扫描 POC 前若干行
# None 表示扫描全文
SCAN_MAX_LINES = None

# 当标头后面为空时，是否尝试读取下一行作为值
TAKE_NEXT_LINE_IF_EMPTY = True

# 下一行取值最多向后看几行
NEXT_LINE_LOOKAHEAD = 2

# 单行过长时跳过，避免把大段代码误识别为 header value
MAX_LINE_LENGTH = 1000

# header value 最大保存长度，避免异常长文本写入
MAX_HEADER_VALUE_LENGTH = 500

# 导出文件
SUMMARY_OUTPUT_FILE = "poc_integrity_summary.json"
DETAIL_OUTPUT_FILE = "poc_integrity_missing_detail.json"


# ============================================================
# 二、9 个目标标头及其别名
# ============================================================

HEADER_ALIASES = {
    "Exploit Title": [
        "Exploit Title",
        "Title Exploit",
        "Exploit Name",
        "Title"
    ],

    "Google Dork": [
        "Google Dork",
        "Google Dorks",
        "Dork",
        "Dorks",
        "Search Dork",
        "Search Dorks"
    ],

    "Date": [
        "Exploit Date",
        "Release Date",
        "Released Date",
        "Disclosure Date",
        "Disclosed Date",
        "Published Date",
        "Publish Date",
        "Public Date",
        "Discovery Date",
        "Discovered Date",
        "Discovered On",
        "Disclosure On",
        "Published On",
        "Date"
    ],

    "Exploit Author": [
        "Exploit Author",
        "Author Exploit",
        "Exploit Writer",
        "Written By",
        "Coded By",
        "Code By",
        "Found By",
        "Finder",
        "Discovered By",
        "Discoverd By",
        "Discovery By",
        "Reported By",
        "Researcher",
        "Author"
    ],

    "Vendor Homepage": [
        "Vendor Homepage",
        "Vendor Home Page",
        "Vendor URL",
        "Vendor Link",
        "Vendor Website",
        "Vendor Web Site",
        "Vendor Site",
        "Vendor URI",
        "Vendor"
    ],

    "Software Link": [
        "Software Link",
        "Link Software",
        "Software URL",
        "Software URI",
        "Software Website",
        "Software Download",
        "Software Buy",
        "Product Link",
        "Product web page",
        "Product URL",
        "Product URI",
        "Application Link",
        "Application URL",
        "App Link",
        "App URL",
        "Software",
        "Script",
        "Product",
        "Application",
        "App"
    ],

    "Version": [
        "Version",
        "Tested Version",
        "Extension Version",
        "Software Version",
        "Product Version",
        "Application Version",
        "App Version",
        "Affected Version",
        "Affected Versions",
        "Vulnerable Version",
        "Vulnerable Versions"
    ],

    "Tested on": [
        "Tested on",
        "Tested on OS",
        "Tested on Operating System",
        "Tested on Platform",
        "Tested on System",
        "Tested OS",
        "Tested Platform",
        "Tested System",
        "Tested under",
        "Tested with",
        "Tested agains",
        "Tested against"
    ],

    "CVE": [
        "CVE ID",
        "CVE IDs",
        "CVEID",
        "CVEIDs",
        "CVE Number",
        "CVE No",
        "CVE编号",
        "CVE"
    ]
}

HEADER_NAMES = list(HEADER_ALIASES.keys())


# ============================================================
# 三、空值规则
# ============================================================

EMPTY_VALUES = {
    "",
    "-",
    "--",
    "---",
    "n/a",
    "na",
    "n.a",
    "none",
    "null",
    "nil",
    "unknown",
    "unknow",
    "not available",
    "not applicable",
    "not found",
    "not specified",
    "not tested",
    "no",
    "nope",
    "?",
    "？"
}


# ============================================================
# 四、正则构建工具
# ============================================================

def make_flexible_alias_pattern(alias):
    """
    将别名转换为更宽松的正则。

    例如：
    Software Link 可以匹配：
    Software Link
    Software-Link
    Software_Link
    Software/Link
    SoftwareLink
    """
    alias = alias.strip()

    # 按空格、下划线、短横线、斜杠拆分
    parts = re.split(r"[\s_\-/]+", alias)
    parts = [p for p in parts if p]

    # 允许词之间出现空格、下划线、短横线、斜杠，也允许没有分隔符
    body = r"[\s_\-/]*".join(re.escape(p) for p in parts)

    # 避免 Date 匹配到 Update 这类词内部
    return rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])"


def build_single_header_regex(canonical_name, alias):
    """
    为某一个别名构造匹配正则。

    支持：
    # Exploit Title: xxx
    # Exploit Title：xxx
    # Exploit Title = xxx
    # Exploit Title - xxx
    // Exploit Title: xxx
    /* Exploit Title: xxx */
    : # Author        : xxx
    [*] Discovered By: xxx
    [+] Discovered On: xxx
    #[+] Dork : xxx
    """

    alias_pattern = make_flexible_alias_pattern(alias)

    # 行首允许：
    # 1. 普通空格；
    # 2. 一个多余的冒号，例如 : # Date : xxx；
    # 3. 注释符号，例如 #、//、/*、*、<!--；
    # 4. EDB 常见标记，例如 [+]、[*]、[-]、[!]；
    #
    # 能匹配：
    # : # Author        : saudi0hacker
    # [*] Discovered By: StAkeR
    # [+] Discovered On: 14 Jul 2008
    # #[+] Dork : "Powered by Rock Band CMS 0.10"
    comment_prefix = (
        r"^\s*"
        r"(?::\s*)?"
        r"(?:[#;]+|//+|/\*+|\*+|<!--)?\s*"
        r"(?:\[[^\]]{1,20}\]\s*){0,3}"
    )

    # 标头和分隔符之间允许空格、点
    middle = r"[\s.]*"

    # 分隔符
    # 注意：
    # 对于单独的 CVE，不允许用短横线作为分隔符，
    # 避免把 "# CVE-2010-1234" 误判为 CVE 标头。
    if canonical_name == "CVE" and alias.strip().lower() == "cve":
        separator = r"(?:[:：=])"
    else:
        separator = r"(?:[:：=]|\s*[-–—]\s*)"

    pattern = (
        comment_prefix
        + alias_pattern
        + middle
        + separator
        + r"\s*"
        + r"(?P<value>.*?)"
        + r"\s*(?:\*/|-->)?\s*$"
    )

    return re.compile(pattern, re.I | re.UNICODE)


def build_all_header_regexes():
    """
    为所有目标标头构造正则。
    返回：
    {
        "Exploit Title": [
            ("Exploit Title", compiled_regex),
            ("Title Exploit", compiled_regex),
            ...
        ],
        ...
    }
    """
    compiled = {}

    for canonical_name, aliases in HEADER_ALIASES.items():
        compiled[canonical_name] = []

        # 长别名优先，避免 Tested on 先于 Tested on OS 匹配
        aliases_sorted = sorted(aliases, key=len, reverse=True)

        for alias in aliases_sorted:
            compiled[canonical_name].append(
                (alias, build_single_header_regex(canonical_name, alias))
            )

    return compiled


COMPILED_HEADERS = build_all_header_regexes()


# ============================================================
# 五、值清洗与判断
# ============================================================

def normalize_header_value(value):
    """
    清洗 header 后面的值。
    """
    if value is None:
        return ""

    value = str(value).strip()

    # 去掉下一行取值时可能带上的注释前缀和符号前缀
    value = re.sub(
        r"^\s*(?::\s*)?(?:[#;]+|//+|/\*+|\*+|<!--)?\s*(?:\[[^\]]{1,20}\]\s*){0,3}",
        "",
        value
    )

    # 去掉 HTML / C 注释尾部
    value = re.sub(r"\s*(?:\*/|-->)\s*$", "", value)

    # 去掉外层引号
    value = value.strip().strip("\"'`").strip()

    # 限制长度
    if len(value) > MAX_HEADER_VALUE_LENGTH:
        value = value[:MAX_HEADER_VALUE_LENGTH].strip()

    return value


def is_empty_style_header_value(value):
    """
    判断 header value 是否属于空值型表达。

    注意：
    这个函数不再用于判断“标头是否存在”。
    当前规则是：只要标头被匹配到，就算存在。

    该函数只用于额外记录：
    该标头虽然存在，但值是 N/A、None、Unknown 等空值型表达。
    """
    value = normalize_header_value(value)

    if value.lower() in EMPTY_VALUES:
        return True

    return False


def is_valid_header_value(value):
    """
    判断 header value 是否有效。

    主要用于：
    1. 当前标头行值为空时，判断下一行是否可以作为有效值；
    2. 与原逻辑兼容。

    注意：
    该函数不再决定标头是否存在。
    """
    return not is_empty_style_header_value(value)


def is_probably_header_line(line):
    """
    判断某一行是否像 header 行。

    主要用于：
    当当前 header value 为空时，尝试读取下一行；
    如果下一行其实是另一个 header，就不能把它当作当前 header 的值。
    """
    if not line:
        return False

    if len(line) > MAX_LINE_LENGTH:
        return False

    for canonical_name in HEADER_NAMES:
        for _, regex in COMPILED_HEADERS[canonical_name]:
            if regex.match(line):
                return True

    return False


def get_next_line_value(lines, current_index):
    """
    当 header 当前行没有值时，尝试从后续 1-2 行读取值。

    例如：
    # Tested on OS:
    Windows 10

    会把 Windows 10 作为 Tested on 的值。
    """
    max_index = min(len(lines), current_index + 1 + NEXT_LINE_LOOKAHEAD)

    for next_index in range(current_index + 1, max_index):
        next_line = lines[next_index]

        if not next_line or not next_line.strip():
            continue

        if len(next_line) > MAX_LINE_LENGTH:
            return ""

        # 下一行如果是另一个 header，就停止
        if is_probably_header_line(next_line):
            return ""

        value = normalize_header_value(next_line)

        if is_valid_header_value(value):
            return value

    return ""


# ============================================================
# 六、核心检测函数
# ============================================================

def analyze_poc_text(text):
    """
    检测一条 POC 文本的 9 个标头存在情况。

    当前核心规则：
    只要某一行匹配到了目标标头，就认为该标头存在。
    即使值为 N/A、None、Unknown、Not Available、- 等，也算存在。
    """
    if text is None:
        text = ""

    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    if SCAN_MAX_LINES is not None:
        scan_lines = lines[:SCAN_MAX_LINES]
    else:
        scan_lines = lines

    result = {
        "found": {},
        "values": {},
        "matched_aliases": {},
        "matched_lines": {},
        "matched_line_numbers": {},
        "empty_matched_lines": {},
        "missing": [],
        "score": 0
    }

    for canonical_name in HEADER_NAMES:
        field_found = False

        for line_index, line in enumerate(scan_lines):
            if not line or not line.strip():
                continue

            if len(line) > MAX_LINE_LENGTH:
                continue

            for alias, regex in COMPILED_HEADERS[canonical_name]:
                match = regex.match(line)

                if not match:
                    continue

                raw_value = match.group("value")
                value = normalize_header_value(raw_value)

                # 如果当前行 value 是空值型表达，例如：
                # # Tested on OS:
                # # Google Dork: N/A
                #
                # 仍然尝试从下一行读取有效值。
                # 但不管下一行有没有值，只要当前行匹配到了标头，就算存在。
                if is_empty_style_header_value(value) and TAKE_NEXT_LINE_IF_EMPTY:
                    value_from_next_line = get_next_line_value(scan_lines, line_index)
                    if is_valid_header_value(value_from_next_line):
                        value = value_from_next_line

                # ====================================================
                # 核心规则：
                # 只要匹配到标头，就认为该标头存在。
                # 不因为 N/A、None、Unknown 等值而判定为缺失。
                # ====================================================
                result["found"][canonical_name] = True
                result["values"][canonical_name] = value
                result["matched_aliases"][canonical_name] = alias
                result["matched_lines"][canonical_name] = line.strip()
                result["matched_line_numbers"][canonical_name] = line_index + 1
                result["score"] += 1
                field_found = True

                # 如果最终 value 仍然是空值型表达，则额外记录
                if is_empty_style_header_value(value):
                    result["empty_matched_lines"][canonical_name] = {
                        "alias": alias,
                        "line": line.strip(),
                        "line_number": line_index + 1,
                        "value": value
                    }

                break

            if field_found:
                break

        if not field_found:
            result["found"][canonical_name] = False
            result["missing"].append(canonical_name)

    return result


# ============================================================
# 七、统计函数
# ============================================================

def summarize_stats(results):
    """
    统计每个 header 的出现次数、缺失次数、完整性分数分布。
    """
    found_totals = {k: 0 for k in HEADER_NAMES}
    missing_totals = {k: 0 for k in HEADER_NAMES}
    score_distribution = defaultdict(int)

    for r in results:
        score_distribution[str(r["score"])] += 1

        for header_name in HEADER_NAMES:
            if r["found"].get(header_name):
                found_totals[header_name] += 1
            else:
                missing_totals[header_name] += 1

    return {
        "found_totals": found_totals,
        "missing_totals": missing_totals,
        "score_distribution": dict(
            sorted(score_distribution.items(), key=lambda x: int(x[0]))
        )
    }


# ============================================================
# 八、主程序
# ============================================================

def main():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    coll = db[COLLECTION_NAME]

    query = {
        POC_FIELD: {
            "$exists": True,
            "$ne": None
        }
    }

    projection = {
        POC_FIELD: 1,
        EDB_ID_FIELD: 1
    }

    total_docs_in_query = coll.count_documents(query)

    cursor = coll.find(query, projection)

    if LIMIT is not None:
        cursor = cursor.limit(LIMIT)
        progress_total = min(LIMIT, total_docs_in_query)
    else:
        progress_total = total_docs_in_query

    print("=" * 80)
    print("开始检测 PoC 标头完整性")
    print(f"MongoDB: {MONGO_URI}")
    print(f"数据库: {DB_NAME}")
    print(f"集合: {COLLECTION_NAME}")
    print(f"POC 字段: {POC_FIELD}")
    print(f"满足条件的文档数: {total_docs_in_query}")
    print(f"本次处理文档数: {progress_total}")
    print(f"是否写回 MongoDB: {WRITE_BACK}")
    print(f"扫描行数限制: {SCAN_MAX_LINES}")
    print("标头判定规则: 匹配到标头即视为存在，N/A/None/Unknown 等也算存在")
    print("=" * 80)

    results = []

    for doc in tqdm(cursor, total=progress_total):
        doc_id = doc.get("_id")
        edb_id = doc.get(EDB_ID_FIELD)
        poc_text = doc.get(POC_FIELD) or ""

        analysis = analyze_poc_text(poc_text)

        integrity_result = {
            "EDB_id": edb_id,
            "found": analysis["found"],
            "values_sample": analysis["values"],
            "matched_aliases": analysis["matched_aliases"],
            "matched_lines": analysis["matched_lines"],
            "matched_line_numbers": analysis["matched_line_numbers"],
            "empty_matched_lines": analysis["empty_matched_lines"],
            "missing": analysis["missing"],
            "score": analysis["score"],
            "max_score": len(HEADER_NAMES)
        }

        if WRITE_BACK:
            coll.update_one(
                {"_id": doc_id},
                {
                    "$set": {
                        "poc_integrity": integrity_result
                    }
                }
            )

        results.append(integrity_result)

    total_processed = len(results)
    stats = summarize_stats(results)

    print("\n" + "=" * 80)
    print("汇总统计")
    print("=" * 80)

    for header_name in HEADER_NAMES:
        found_count = stats["found_totals"][header_name]
        missing_count = stats["missing_totals"][header_name]
        found_pct = found_count / total_processed * 100 if total_processed else 0
        missing_pct = missing_count / total_processed * 100 if total_processed else 0

        print(
            f"{header_name:18s} "
            f"存在: {found_count:6d}/{total_processed:<6d} ({found_pct:6.2f}%)   "
            f"缺失: {missing_count:6d}/{total_processed:<6d} ({missing_pct:6.2f}%)"
        )

    print("\n完整性分数分布：")
    for score, count in stats["score_distribution"].items():
        pct = count / total_processed * 100 if total_processed else 0
        print(f"score={score:>2s}: {count:6d} ({pct:6.2f}%)")

    summary_output = {
        "config": {
            "mongo_uri": MONGO_URI,
            "db_name": DB_NAME,
            "collection_name": COLLECTION_NAME,
            "poc_field": POC_FIELD,
            "edb_id_field": EDB_ID_FIELD,
            "write_back": WRITE_BACK,
            "limit": LIMIT,
            "scan_max_lines": SCAN_MAX_LINES,
            "take_next_line_if_empty": TAKE_NEXT_LINE_IF_EMPTY,
            "next_line_lookahead": NEXT_LINE_LOOKAHEAD,
            "header_existence_rule": "matched_header_is_counted_as_existing_even_if_value_is_NA_None_Unknown",
            "extra_supported_prefixes": [
                ": #",
                "[*]",
                "[+]",
                "#[+]"
            ],
            "extra_supported_aliases": {
                "Exploit Author": [
                    "Found By",
                    "Discovered By",
                    "Discoverd By",
                    "Reported By"
                ],
                "Software Link": [
                    "Software",
                    "Product",
                    "Application",
                    "App"
                ],
                "Date": [
                    "Discovered On",
                    "Discovered Date"
                ],
                "Google Dork": [
                    "Dork"
                ]
            }
        },
        "total_docs_in_query": total_docs_in_query,
        "total_processed": total_processed,
        "headers": HEADER_NAMES,
        "stats": stats
    }

    detail_output = []

    for index, r in enumerate(results):
        detail_output.append({
            "index": index,
            "EDB_id": r.get("EDB_id"),
            "score": r.get("score"),
            "max_score": r.get("max_score"),
            "missing": r.get("missing"),
            "found": r.get("found"),
            "values_sample": r.get("values_sample"),
            "matched_aliases": r.get("matched_aliases"),
            "matched_line_numbers": r.get("matched_line_numbers"),
            "matched_lines": r.get("matched_lines"),
            "empty_matched_lines": r.get("empty_matched_lines")
        })

    with open(SUMMARY_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(summary_output, f, ensure_ascii=False, indent=2)

    with open(DETAIL_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(detail_output, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 80)
    print("检测完成")
    print(f"汇总统计已导出: {SUMMARY_OUTPUT_FILE}")
    print(f"缺失明细已导出: {DETAIL_OUTPUT_FILE}")

    if WRITE_BACK:
        print("检测结果已写回 MongoDB 字段: poc_integrity")

    print("=" * 80)

    client.close()


if __name__ == "__main__":
    main()
