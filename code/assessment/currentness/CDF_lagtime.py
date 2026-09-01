# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# =========================
# Configuration
# =========================
INPUT_TXT = r"EDB_date_compare_diff.txt"
OUTPUT_FIG = "cdf_edb_lag_times.png"

TOP_K = 10   # remove the largest Top 10 absolute differences internally


def main():
    # =========================
    # Read data
    # =========================
    df = pd.read_csv(
        INPUT_TXT,
        sep="\t",
        dtype=str,
        keep_default_na=False
    )

    df["diff_days_signed_num"] = pd.to_numeric(df["diff_days_signed"], errors="coerce")
    df["diff_days_abs_num"] = pd.to_numeric(df["diff_days_abs"], errors="coerce")
    df["EDB_id_num"] = pd.to_numeric(df["EDB_id"], errors="coerce")

    # =========================
    # Keep only successfully parsed records
    # =========================
    success_df = df[df["status"] == "success"].copy()
    success_df = success_df.dropna(subset=["diff_days_signed_num", "diff_days_abs_num"])

    # =========================
    # Remove the largest Top-K absolute differences
    # This step is only for data filtering, not shown in the title.
    # =========================
    topk_df = success_df.sort_values(
        by=["diff_days_abs_num", "EDB_id_num"],
        ascending=[False, True],
        kind="mergesort"
    ).head(TOP_K)

    normal_df = success_df.drop(index=topk_df.index).copy()

    # =========================
    # Compute lag time
    # Original:
    # diff_days_signed = primary_date - EDB Date
    #
    # Therefore:
    # lag_days = EDB Date - primary_date = -diff_days_signed
    # =========================
    normal_df["lag_days"] = -normal_df["diff_days_signed_num"]

    # Keep only non-negative lag times
    lag_df = normal_df[normal_df["lag_days"] >= 0].copy()

    lag_values = np.sort(lag_df["lag_days"].to_numpy())
    n = len(lag_values)

    if n == 0:
        print("No valid lag-time data for plotting.")
        return

    cdf = np.arange(1, n + 1) / n

    no_lag_count = int((lag_values == 0).sum())
    no_lag_ratio = no_lag_count / n * 100

    # =========================
    # Plot
    # =========================
    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(
        lag_values,
        cdf,
        color="black",
        linewidth=3
    )

    ax.set_xlabel("Lag Time (days)", fontsize=20)
    ax.set_ylabel("CDF", fontsize=20)

    # Clean title: no "normal data", no "Top10 removed"
    ax.set_title(
        "CDF of EDB Lag Times",
        fontsize=26,
        fontweight="bold",
        pad=14
    )

    ax.set_ylim(0, 1.02)
    ax.set_xlim(0, np.percentile(lag_values, 99.5))

    ax.grid(axis="y", alpha=0.25, linewidth=1.2)

    ax.tick_params(axis="x", labelsize=20, width=1.8, length=8)
    ax.tick_params(axis="y", labelsize=20, width=1.8, length=8)

    for spine in ax.spines.values():
        spine.set_linewidth(1.8)

    # Caption: no mention of deleted data
    caption = (
        f"Lag time = EDB Date - primary_date. "
        f"n={n:,}; {no_lag_ratio:.2f}% records have no lag."
    )

    plt.figtext(
        0.02,
        -0.04,
        caption,
        ha="left",
        fontsize=18
    )

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    plt.savefig(OUTPUT_FIG, dpi=300, bbox_inches="tight")
    plt.show()

    print("Done.")
    print(f"Figure saved to: {OUTPUT_FIG}")
    print(f"n = {n:,}")
    print(f"No lag: {no_lag_count:,} ({no_lag_ratio:.2f}%)")
    print(f"Median lag: {np.median(lag_values):.0f} days")
    print(f"Mean lag: {np.mean(lag_values):.2f} days")
    print(f"Max lag in plot data: {np.max(lag_values):.0f} days")


if __name__ == "__main__":
    main()