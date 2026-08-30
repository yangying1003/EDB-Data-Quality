from pygments import lex
from pygments.lexers import guess_lexer, ClassNotFound
from pygments.token import Token

# ----------------------------
# 一、你原来的整篇判定函数（未改动）
# ----------------------------
def detect_code_with_pygments_v4(content: str,
                                 token_ratio_threshold: float = 0.12,
                                 code_line_ratio_threshold: float = 0.30,
                                 min_code_lines: int = 8):
    try:
        lexer = guess_lexer(content)
    except ClassNotFound:
        return {
            "is_code": False,
            "token_ratio": 0.0,
            "code_line_ratio": 0.0,
            "code_lines": 0,
            "total_nonempty_lines": len([l for l in content.splitlines() if l.strip()]),
            "reason": "pygments 无法猜测语言 (ClassNotFound)"
        }

    lexer_name = getattr(lexer, "name", "").lower()
    if "text" in lexer_name and "html" not in lexer_name:
        return {
            "is_code": False,
            "token_ratio": 0.0,
            "code_line_ratio": 0.0,
            "code_lines": 0,
            "total_nonempty_lines": len([l for l in content.splitlines() if l.strip()]),
            "reason": f"猜测为纯文本 lexer: {lexer_name}"
        }

    tokens = list(lex(content, lexer))
    non_ws_tokens = 0
    code_like_tokens = 0

    def is_code_token(ttype):
        return (
            (ttype in Token.Keyword) or
            (ttype in Token.Operator) or
            (ttype in Token.Punctuation) or
            (ttype in Token.Literal.String) or
            (ttype in Token.Literal.Number)
        )

    for ttype, val in tokens:
        if not val or val.isspace():
            continue
        non_ws_tokens += 1
        if is_code_token(ttype):
            code_like_tokens += 1

    token_ratio = (code_like_tokens / non_ws_tokens) if non_ws_tokens else 0.0

    code_keywords = ["def", "class", "if", "else", "elif", "for", "while", "return",
                     "function", "var", "let", "const", "=>", "->", "import", "from",
                     "package", "public", "private", "protected", "try", "except",
                     "#include", "namespace", "using", "<?php", "?>" ]
    code_symbols = set("{}();[];=+-*/%&|^!@\\<>")
    code_line_count = 0
    total_nonempty_lines = 0

    in_fenced_block = False
    lines = content.splitlines()
    for idx, raw_line in enumerate(lines):
        s = raw_line.strip()
        if not s:
            continue
        total_nonempty_lines += 1

        if s.startswith("```"):
            in_fenced_block = not in_fenced_block
            continue
        if in_fenced_block:
            continue

        lower = s.lower()
        if s.startswith("#") and len(s) > 1 and any(ch.isalpha() for ch in s[1:5]):
            continue
        if "http://" in s or "https://" in s:
            continue
        if lower.startswith(("payload:", "steps:", "video poc:", "full write-up", "full write-up & repository", "example payload", "example payload url")):
            continue
        if s.startswith(("-", "*")):
            continue
        if any(s.startswith(f"{n}.") for n in range(1, 100)):
            continue
        if "`" in s:
            continue

        if s.upper().startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
            continue
        http_headers = ("host:", "user-agent:", "referer:", "accept:", "content-type:", "content-length:", "cookie:")
        if any(s.lower().startswith(h) for h in http_headers):
            continue

        if (("<script" in s or "</script>" in s or "svg/onload" in s or "onload=" in s)
            and len(s) < 200 and s.count("<") <= 2):
            continue

        kw_found = any((" " + kw + " " in (" " + lower + " ")) or lower.startswith(kw + " ") or lower.endswith(" " + kw) or lower == kw for kw in code_keywords)
        symbol_count = sum(s.count(sym) for sym in code_symbols)

        is_code_line = False
        if symbol_count >= 5:
            is_code_line = True
        elif s.endswith(";"):
            is_code_line = True
        elif kw_found:
            is_code_line = True
        elif 1 <= symbol_count <= 4 and len(s) < 60 and any(ch in "<>/" for ch in s):
            is_code_line = False

        if is_code_line:
            code_line_count += 1

    code_line_ratio = (code_line_count / total_nonempty_lines) if total_nonempty_lines else 0.0
    is_code = (token_ratio >= token_ratio_threshold or code_line_ratio >= code_line_ratio_threshold) and (code_line_count >= min_code_lines)

    reason = f"guessed lexer: {lexer_name} | token_ratio={token_ratio:.3f} | code-line ratio={code_line_ratio:.3f}, code_lines={code_line_count}/{total_nonempty_lines}"

    return {
        "is_code": bool(is_code),
        "token_ratio": token_ratio,
        "code_line_ratio": code_line_ratio,
        "code_lines": code_line_count,
        "total_nonempty_lines": total_nonempty_lines,
        "reason": reason
    }

# ----------------------------
# 二、从你的行级逻辑中抽出 code-line 判断
# ----------------------------
def is_code_like_line(line: str):
    code_keywords = ["def", "class", "if", "else", "elif", "for", "while", "return",
                     "function", "var", "let", "const", "=>", "->", "import", "from",
                     "package", "public", "private", "protected", "try", "except",
                     "#include", "namespace", "using", "<?php", "?>" ]
    code_symbols = set("{}();[];=+-*/%&|^!@\\<>")

    raw = line
    s = line.strip()
    if not s:
        return False

    if s.startswith(("payload:", "steps:", "video poc:", "full write-up", "example payload")):
        return False
    if s.startswith(("-", "*")) or any(s.startswith(f"{n}.") for n in range(1, 100)):
        return False
    if "http://" in s or "https://" in s:
        return False
    if "`" in s:
        return False

    lower = s.lower()

    kw_found = any(
        (" " + kw + " " in (" " + lower + " ")) or lower.startswith(kw + " ")
        or lower.endswith(" " + kw) or lower == kw
        for kw in code_keywords
    )

    symbol_count = sum(s.count(sym) for sym in code_symbols)

    if symbol_count >= 5:
        return True
    if s.endswith(";"):
        return True
    if kw_found:
        return True

    return False

# ----------------------------
# 三、提取代码块 + 删除代码块
# ----------------------------
def extract_code_blocks(content: str):
    lines = content.splitlines()
    code_blocks = []
    current_block = None

    for idx, line in enumerate(lines):
        if is_code_like_line(line):
            if current_block is None:
                current_block = {"start": idx, "lines": []}
            current_block["lines"].append(line)
        else:
            if current_block is not None:
                current_block["end"] = idx - 1
                code_blocks.append(current_block)
                current_block = None

    if current_block is not None:
        current_block["end"] = len(lines) - 1
        code_blocks.append(current_block)

    # 删除这些行
    to_delete = set()
    for blk in code_blocks:
        for i in range(blk["start"], blk["end"] + 1):
            to_delete.add(i)

    cleaned_lines = [
        line for i, line in enumerate(lines) if i not in to_delete
    ]
    cleaned_text = "\n".join(cleaned_lines)

    return code_blocks, cleaned_text

# ----------------------------
# 四、主程序：读取文件 → 提取 → 输出
# ----------------------------
if __name__ == "__main__":
    import sys
    path = "poc1.txt" if len(sys.argv) == 1 else sys.argv[1]

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 运行你的判定逻辑
    res = detect_code_with_pygments_v4(content)
    print("是否包含代码？", res["is_code"])
    print("诊断：", res["reason"])

    # 提取 + 删除
    blocks, cleaned = extract_code_blocks(content)

    print("\n检测到代码块数量：", len(blocks))
    for b in blocks:
        print(f"> 代码块: 行 {b['start']} 到 {b['end']}")

    # 输出清理后的文件
    out_path = path + ".cleaned.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(cleaned)

    print("\n已生成清理后的文件:", out_path)
