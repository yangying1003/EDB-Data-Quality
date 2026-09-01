# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import matplotlib

# 避免 PyCharm 后端 tostring_rgb 报错，只保存图片，不弹窗
matplotlib.use("Agg")

import matplotlib.pyplot as plt
from pathlib import Path


# =========================
# 配置区
# =========================
INPUT_TXT = r"EDB_date_compare_diff.txt"

OUTPUT_ROOT = Path("EDB_date_topK_analysis")

# 同时生成 Top10 和 Top20 两套图
TOP_K_LIST = [10, 20]

# CDF 图横轴最大值
# None 表示自动使用 99.5% 分位数，避免极端长尾把图压扁
# 也可以手动改成 365、1000、2000
CDF_XMAX = None


# =========================
# 画图字体设置
# =========================
plt.rcParams["font.sans-serif"] = [
    "Microsoft YaHei",
    "SimHei",
    "Arial Unicode MS",
    "DejaVu Sans"
]
plt.rcParams["axes.unicode_minus"] = False


def pct(n, total):
    return n / total * 100 if total else 0


def read_data(input_txt):
    df = pd.read_csv(
        input_txt,
        sep="\t",
        dtype=str,
        keep_default_na=False
    )

    df["diff_days_signed_num"] = pd.to_numeric(
        df["diff_days_signed"],
        errors="coerce"
    )

    df["diff_days_abs_num"] = pd.to_numeric(
        df["diff_days_abs"],
        errors="coerce"
    )

    df["EDB_id_num"] = pd.to_numeric(
        df["EDB_id"],
        errors="coerce"
    )

    return df


def split_data_by_topk(df, top_k):
    """
    先排除 parse_failed，再从 success 数据中删除 diff_days_abs 最大的 top_k 条。
    """

    total_df = df.copy()

    parse_failed_df = total_df[total_df["status"] != "success"].copy()

    success_df = total_df[total_df["status"] == "success"].copy()
    success_df = success_df.dropna(subset=["diff_days_abs_num"])

    # 按绝对差异从大到小排序，取最大的 top_k 条作为异常
    topk_abnormal_df = success_df.sort_values(
        by=["diff_days_abs_num", "EDB_id_num"],
        ascending=[False, True],
        kind="mergesort"
    ).head(top_k).copy()

    # 剩下的是正常分析数据
    normal_df = success_df.drop(index=topk_abnormal_df.index).copy()

    return total_df, parse_failed_df, topk_abnormal_df, normal_df


def add_bar_labels(ax, bars, counts, total, horizontal=False):
    if horizontal:
        max_value = max(counts) if len(counts) else 1
        for bar, count in zip(bars, counts):
            width = bar.get_width()
            ax.text(
                width + max_value * 0.015,
                bar.get_y() + bar.get_height() / 2,
                f"{count:,}\n({pct(count, total):.2f}%)",
                va="center",
                ha="left",
                fontsize=10
            )
    else:
        max_value = max(counts) if len(counts) else 1
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + max_value * 0.015,
                f"{count:,}\n({pct(count, total):.2f}%)",
                va="bottom",
                ha="center",
                fontsize=10
            )


def plot_filter_result(total_df, parse_failed_df, topk_abnormal_df, normal_df, out_dir, top_k):
    labels = [
        "原始总记录数",
        "解析失败\n暂不分析",
        f"删除最大差异\nTop{top_k}",
        "进入正常分析\n的数据"
    ]

    counts = [
        len(total_df),
        len(parse_failed_df),
        len(topk_abnormal_df),
        len(normal_df)
    ]

    colors = ["#2f66c5", "#6fa3ef", "#f39c12", "#2e8b57"]

    fig, ax = plt.subplots(figsize=(8, 4.8))

    bars = ax.barh(labels, counts, color=colors)
    ax.invert_yaxis()

    add_bar_labels(ax, bars, counts, len(total_df), horizontal=True)

    ax.set_xlabel("记录数（条）", fontsize=12)
    ax.set_title(
        f"数据筛选结果：剔除解析失败与最大差异 Top{top_k}",
        fontsize=14,
        fontweight="bold"
    )

    ax.grid(axis="x", alpha=0.25)
    ax.set_xlim(0, max(counts) * 1.25)

    plt.tight_layout()
    fig.savefig(out_dir / f"01_filter_result_top{top_k}.png", dpi=300)
    plt.close(fig)


def plot_direction(normal_df, out_dir, top_k):
    total = len(normal_df)

    same_count = (normal_df["diff_days_signed_num"] == 0).sum()
    earlier_count = (normal_df["diff_days_signed_num"] < 0).sum()
    later_count = (normal_df["diff_days_signed_num"] > 0).sum()

    labels = [
        "日期完全相同",
        "primary_date\n早于 EDB Date",
        "primary_date\n晚于 EDB Date"
    ]

    counts = [same_count, earlier_count, later_count]
    colors = ["#2f66c5", "#2e8b57", "#f39c12"]

    fig, ax = plt.subplots(figsize=(8, 4.8))

    bars = ax.barh(labels, counts, color=colors)
    ax.invert_yaxis()

    add_bar_labels(ax, bars, counts, total, horizontal=True)

    ax.set_xlabel("记录数（条）", fontsize=12)
    ax.set_title(
        f"正常数据中日期差异方向（删除最大差异 Top{top_k} 后，n={total:,}）",
        fontsize=14,
        fontweight="bold"
    )

    ax.grid(axis="x", alpha=0.25)
    ax.set_xlim(0, max(counts) * 1.25)

    plt.tight_layout()
    fig.savefig(out_dir / f"02_date_direction_top{top_k}.png", dpi=300)
    plt.close(fig)


def plot_abs_diff_bucket(normal_df, out_dir, top_k):
    total = len(normal_df)
    s = normal_df["diff_days_abs_num"]

    bucket_defs = [
        ("0 天", s == 0),
        ("1–7 天", (s >= 1) & (s <= 7)),
        ("8–14 天", (s >= 8) & (s <= 14)),
        ("15–30 天", (s >= 15) & (s <= 30)),
        ("31–90 天", (s >= 31) & (s <= 90)),
        ("91–180 天", (s >= 91) & (s <= 180)),
        ("181–365 天", (s >= 181) & (s <= 365)),
        (">365 天", s > 365),
    ]

    labels = [x[0] for x in bucket_defs]
    counts = [int(x[1].sum()) for x in bucket_defs]

    fig, ax = plt.subplots(figsize=(10, 5.2))

    bars = ax.bar(labels, counts, color="#2f66c5")

    add_bar_labels(ax, bars, counts, total, horizontal=False)

    ax.set_ylabel("记录数（条）", fontsize=12)
    ax.set_xlabel("绝对日期差异（天）", fontsize=12)
    ax.set_title(
        f"绝对日期差异分布（删除最大差异 Top{top_k} 后，n={total:,}）",
        fontsize=14,
        fontweight="bold"
    )

    ax.grid(axis="y", alpha=0.25)
    ax.set_ylim(0, max(counts) * 1.25)

    plt.xticks(rotation=30)
    plt.tight_layout()
    fig.savefig(out_dir / f"03_abs_diff_bucket_top{top_k}.png", dpi=300)
    plt.close(fig)


def plot_cumulative_distribution(normal_df, out_dir, top_k):
    total = len(normal_df)
    s = normal_df["diff_days_abs_num"]

    thresholds = [7, 14, 30, 90, 180, 365]
    labels = [f"≤ {t} 天" for t in thresholds]
    counts = [int((s <= t).sum()) for t in thresholds]
    ratios = [pct(c, total) for c in counts]

    fig, ax = plt.subplots(figsize=(8.5, 5))

    bars = ax.bar(labels, ratios, color="#2e8b57")

    for bar, ratio, count in zip(bars, ratios, counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{ratio:.2f}%\n({count:,})",
            ha="center",
            va="bottom",
            fontsize=10
        )

    ax.set_ylabel("累计比例（%）", fontsize=12)
    ax.set_xlabel("阈值（绝对日期差异 ≤）", fontsize=12)
    ax.set_title(
        f"绝对日期差异累计分布（删除最大差异 Top{top_k} 后）",
        fontsize=14,
        fontweight="bold"
    )

    ax.set_ylim(0, 105)
    ax.grid(axis="y", alpha=0.25)

    plt.tight_layout()
    fig.savefig(out_dir / f"04_cumulative_distribution_top{top_k}.png", dpi=300)
    plt.close(fig)


def plot_abs_cdf(normal_df, out_dir, top_k):
    values = np.sort(normal_df["diff_days_abs_num"].dropna().to_numpy())
    total = len(values)

    if total == 0:
        return

    cdf = np.arange(1, total + 1) / total

    if CDF_XMAX is None:
        xmax = int(np.percentile(values, 99.5))
        xmax = max(xmax, 30)
    else:
        xmax = CDF_XMAX

    fig, ax = plt.subplots(figsize=(7.2, 4.3))

    ax.plot(values, cdf, color="black", linewidth=2)

    ax.set_xlabel("Absolute Date Difference (days)", fontsize=13)
    ax.set_ylabel("CDF", fontsize=13)
    ax.set_title(
        f"CDF of absolute date differences, Top{top_k} removed",
        fontsize=13,
        fontweight="bold"
    )

    ax.set_xlim(0, xmax)
    ax.set_ylim(0, 1.02)

    ax.grid(axis="y", alpha=0.25)

    note = (
        f"n={total:,}; removed the largest Top{top_k} absolute differences. "
        f"Median={np.median(values):.0f} days; Mean={np.mean(values):.2f} days."
    )

    plt.figtext(
        0.02,
        -0.04,
        note,
        ha="left",
        fontsize=10
    )

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    fig.savefig(out_dir / f"05_abs_diff_cdf_top{top_k}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_lag_cdf(normal_df, out_dir, top_k):
    """
    画 EDB 滞后时间 CDF。
    之前定义：
    diff_days_signed = primary_date - EDB Date

    所以：
    lag_days = EDB Date - primary_date = -diff_days_signed

    这里只保留 lag_days >= 0 的记录。
    """

    temp = normal_df.copy()
    temp["lag_days"] = -temp["diff_days_signed_num"]
    temp = temp[temp["lag_days"] >= 0]

    values = np.sort(temp["lag_days"].dropna().to_numpy())
    total = len(values)

    if total == 0:
        return

    cdf = np.arange(1, total + 1) / total

    if CDF_XMAX is None:
        xmax = int(np.percentile(values, 99.5))
        xmax = max(xmax, 30)
    else:
        xmax = CDF_XMAX

    no_lag_count = int((values == 0).sum())
    no_lag_ratio = pct(no_lag_count, total)

    fig, ax = plt.subplots(figsize=(7.2, 4.3))

    ax.plot(values, cdf, color="black", linewidth=2)

    ax.set_xlabel("Lag Time (days)", fontsize=13)
    ax.set_ylabel("CDF", fontsize=13)
    ax.set_title(
        f"CDF of EDB lag times, Top{top_k} removed",
        fontsize=13,
        fontweight="bold"
    )

    ax.set_xlim(0, xmax)
    ax.set_ylim(0, 1.02)

    ax.grid(axis="y", alpha=0.25)

    note = (
        f"Lag time = EDB Date - primary_date. "
        f"n={total:,}; {no_lag_ratio:.2f}% records have no lag."
    )

    plt.figtext(
        0.02,
        -0.04,
        note,
        ha="left",
        fontsize=10
    )

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    fig.savefig(out_dir / f"06_lag_time_cdf_top{top_k}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def save_summary(total_df, parse_failed_df, topk_abnormal_df, normal_df, out_dir, top_k):
    total = len(total_df)
    normal_count = len(normal_df)

    s_abs = normal_df["diff_days_abs_num"]
    s_signed = normal_df["diff_days_signed_num"]

    same_count = int((s_signed == 0).sum())
    earlier_count = int((s_signed < 0).sum())
    later_count = int((s_signed > 0).sum())

    thresholds = [7, 14, 30, 90, 180, 365]

    lines = []

    lines.append(f"========== Top{top_k} 最大异常剔除分析 ==========")
    lines.append("")
    lines.append("筛选规则：")
    lines.append("1. status != success 的解析失败记录暂不分析")
    lines.append(f"2. 在 status == success 的记录中，删除 diff_days_abs 最大的 Top{top_k} 条")
    lines.append("3. 剩余记录进入正常统计分析")
    lines.append("")

    lines.append("========== 数据量 ==========")
    lines.append(f"原始总记录数: {total}")
    lines.append(f"解析失败记录数: {len(parse_failed_df)} ({pct(len(parse_failed_df), total):.2f}%)")
    lines.append(f"删除最大差异 Top{top_k}: {len(topk_abnormal_df)} ({pct(len(topk_abnormal_df), total):.2f}%)")
    lines.append(f"进入正常分析的数据: {normal_count} ({pct(normal_count, total):.2f}%)")
    lines.append("")

    lines.append("========== 日期差异方向 ==========")
    lines.append(f"日期完全相同: {same_count} ({pct(same_count, normal_count):.2f}%)")
    lines.append(f"primary_date 早于 EDB Date: {earlier_count} ({pct(earlier_count, normal_count):.2f}%)")
    lines.append(f"primary_date 晚于 EDB Date: {later_count} ({pct(later_count, normal_count):.2f}%)")
    lines.append("")

    lines.append("========== 绝对日期差异累计分布 ==========")
    for t in thresholds:
        c = int((s_abs <= t).sum())
        lines.append(f"<= {t} 天: {c} ({pct(c, normal_count):.2f}%)")
    lines.append("")

    lines.append("========== 统计值 ==========")
    lines.append(f"平均绝对差异: {s_abs.mean():.2f} 天")
    lines.append(f"中位数绝对差异: {s_abs.median():.0f} 天")
    lines.append(f"Q1: {s_abs.quantile(0.25):.0f} 天")
    lines.append(f"Q3: {s_abs.quantile(0.75):.0f} 天")
    lines.append(f"最大绝对差异: {s_abs.max():.0f} 天")
    lines.append("")

    lines.append(f"========== 被删除的 Top{top_k} 最大差异记录 ==========")
    for _, row in topk_abnormal_df.iterrows():
        lines.append(
            f"EDB_id={row.get('EDB_id')}, "
            f"primary_date={row.get('primary_date_raw')}, "
            f"EDB_Date={row.get('edb_Date_raw')}, "
            f"diff_days_signed={row.get('diff_days_signed')}, "
            f"diff_days_abs={row.get('diff_days_abs')}"
        )

    summary_path = out_dir / f"summary_top{top_k}.txt"
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    # 输出正常数据和被删除的异常数据
    normal_df.drop(
        columns=["diff_days_signed_num", "diff_days_abs_num", "EDB_id_num"],
        errors="ignore"
    ).to_csv(
        out_dir / f"normal_data_top{top_k}.txt",
        sep="\t",
        index=False,
        encoding="utf-8"
    )

    topk_abnormal_df.drop(
        columns=["diff_days_signed_num", "diff_days_abs_num", "EDB_id_num"],
        errors="ignore"
    ).to_csv(
        out_dir / f"removed_top{top_k}_largest_diff.txt",
        sep="\t",
        index=False,
        encoding="utf-8"
    )


def run_for_topk(df, top_k):
    out_dir = OUTPUT_ROOT / f"top{top_k}"
    out_dir.mkdir(parents=True, exist_ok=True)

    total_df, parse_failed_df, topk_abnormal_df, normal_df = split_data_by_topk(
        df,
        top_k
    )

    save_summary(
        total_df,
        parse_failed_df,
        topk_abnormal_df,
        normal_df,
        out_dir,
        top_k
    )

    plot_filter_result(
        total_df,
        parse_failed_df,
        topk_abnormal_df,
        normal_df,
        out_dir,
        top_k
    )

    plot_direction(
        normal_df,
        out_dir,
        top_k
    )

    plot_abs_diff_bucket(
        normal_df,
        out_dir,
        top_k
    )

    plot_cumulative_distribution(
        normal_df,
        out_dir,
        top_k
    )

    plot_abs_cdf(
        normal_df,
        out_dir,
        top_k
    )

    plot_lag_cdf(
        normal_df,
        out_dir,
        top_k
    )

    print(f"\n========== Top{top_k} 处理完成 ==========")
    print(f"输出目录: {out_dir.resolve()}")
    print(f"正常分析数据量: {len(normal_df)}")
    print(f"删除最大差异记录数: {len(topk_abnormal_df)}")


def main():
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    df = read_data(INPUT_TXT)

    for top_k in TOP_K_LIST:
        run_for_topk(df, top_k)

    print("\n全部完成。")


if __name__ == "__main__":
    main()