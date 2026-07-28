import sys
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # non-interactive backend -- works without display
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

# ── Paths ──────────────────────────────────────────────────────────────────────
CSV_INPUT    = "data/scored_risks.csv"
HEATMAP_OUT  = "reports/risk_heatmap.png"
BARCHART_OUT = "reports/brs_distribution.png"
os.makedirs("reports", exist_ok=True)


# ── Colour scheme for risk levels ─────────────────────────────────────────────
COLOURS = {
    "Critical": "#D7263D",
    "High":     "#F4A226",
    "Medium":   "#F4E04D",
    "Low":      "#4CAF50",
}

# ── Heat map matrix definition ────────────────────────────────────────────────
# Rows = Impact (top = highest), Cols = Likelihood (left = lowest)
LIKELIHOOD_LABELS = ["Very Low\n(1)", "Low\n(2)", "Medium\n(3)", "High\n(4)", "Very High\n(5)"]
IMPACT_LABELS     = ["Critical\n(5)", "Major\n(4)", "Moderate\n(3)", "Minor\n(2)", "Negligible\n(1)"]

# Colour zones for each cell [impact_row][likelihood_col]
# Impact rows: 0=Critical(5), 1=Major(4), 2=Moderate(3), 3=Minor(2), 4=Negligible(1)
# Likelihood cols: 0=VeryLow(1), 1=Low(2), 2=Medium(3), 3=High(4), 4=VeryHigh(5)
HEATMAP_ZONES = [
    ["Medium",   "High",     "High",     "Critical", "Critical"],  # Impact=Critical
    ["Low",      "Medium",   "High",     "High",     "Critical"],  # Impact=Major
    ["Low",      "Medium",   "Medium",   "High",     "High"    ],  # Impact=Moderate
    ["Low",      "Low",      "Medium",   "Medium",   "High"    ],  # Impact=Minor
    ["Low",      "Low",      "Low",      "Low",      "Medium"  ],  # Impact=Negligible
]

# Scores for each cell (Likelihood x Impact)
HEATMAP_SCORES = [
    [3,  8,  12, 20, 25],
    [2,  6,  8,  16, 20],
    [1,  4,  6,  12, 15],
    [1,  2,  4,  6,  10],
    [1,  1,  2,  3,  5 ],
]


def load_data(path: str) -> pd.DataFrame:
    """Load scored_risks.csv into a pandas DataFrame."""
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}")
        print("  Run vuln_puller.py first to generate scored_risks.csv")
        sys.exit(1)

    df = pd.read_csv(path, encoding="utf-8-sig")

    if df.empty:
        print("[ERROR] scored_risks.csv is empty. Run vuln_puller.py first.")
        sys.exit(1)

    print(f"[INFO] Loaded {len(df)} CVE records from {path}")
    return df


def analyse(df: pd.DataFrame) -> None:
    """Print a pandas-powered analysis to terminal."""
    print("\n" + "=" * 65)
    print("  SECUREGRC -- BRS ANALYSIS REPORT")
    print("=" * 65)

    # Summary stats
    print("\n  BRS Score Statistics:")
    print(f"  {'Mean BRS':<20} {df['BRS'].mean():.2f}")
    print(f"  {'Max BRS':<20} {df['BRS'].max():.2f}")
    print(f"  {'Min BRS':<20} {df['BRS'].min():.2f}")
    print(f"  {'Std Dev':<20} {df['BRS'].std():.2f}")

    # Count by classification
    print("\n  Risk Distribution:")
    counts = df["BRS_Classification"].value_counts()
    for level in ["Critical", "High", "Medium", "Low"]:
        count = counts.get(level, 0)
        pct   = (count / len(df)) * 100
        bar   = "|" * min(int(pct / 2), 30)
        print(f"  {level:<10} {bar:<30} {count:>3} ({pct:.1f}%)")

    # Top 10 by BRS
    print("\n  TOP 10 HIGHEST BRS VULNERABILITIES:")
    top10 = df.nlargest(10, "BRS")[
        ["CVE_ID", "Published_Date", "Asset_Name", "CVSS_Score", "BRS", "BRS_Classification"]
    ]
    print(f"  {'CVE ID':<20} {'Published':<12} {'Asset':<28} {'CVSS':<6} {'BRS':<6} Class")
    print("  " + "-" * 78)
    for _, row in top10.iterrows():
        print(
            f"  {row['CVE_ID']:<20} "
            f"{row['Published_Date']:<12} "
            f"{row['Asset_Name']:<28} "
            f"{row['CVSS_Score']:<6} "
            f"{row['BRS']:<6} "
            f"{row['BRS_Classification']}"
        )

    # Per-asset summary
    print("\n  PER-ASSET RISK SUMMARY:")
    asset_summary = df.groupby("Asset_Name").agg(
        CVE_Count=("CVE_ID", "count"),
        Avg_BRS=("BRS", "mean"),
        Max_BRS=("BRS", "max"),
        Critical=("BRS_Classification", lambda x: (x == "Critical").sum()),
        High=("BRS_Classification",     lambda x: (x == "High").sum()),
    ).reset_index()
    asset_summary = asset_summary.sort_values("Max_BRS", ascending=False)

    print(f"  {'Asset':<30} {'CVEs':<6} {'Avg BRS':<9} {'Max BRS':<9} {'Crit':<6} High")
    print("  " + "-" * 65)
    for _, row in asset_summary.iterrows():
        print(
            f"  {row['Asset_Name']:<30} "
            f"{int(row['CVE_Count']):<6} "
            f"{row['Avg_BRS']:<9.2f} "
            f"{row['Max_BRS']:<9.2f} "
            f"{int(row['Critical']):<6} "
            f"{int(row['High'])}"
        )

    print("=" * 65)


def generate_heatmap() -> None:
    """
    Generate a 5x5 ISO 27001-style risk heat map.
    Colours based on Likelihood x Impact zones configured in Eramba.
    Saved as reports/risk_heatmap.png
    """
    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor("#1E1E2E")
    ax.set_facecolor("#1E1E2E")

    # Draw cells
    for row in range(5):
        for col in range(5):
            zone  = HEATMAP_ZONES[row][col]
            score = HEATMAP_SCORES[row][col]
            color = COLOURS[zone]

            rect = mpatches.FancyBboxPatch(
                (col + 0.05, 4 - row + 0.05),
                0.9, 0.9,
                boxstyle="round,pad=0.02",
                facecolor=color,
                edgecolor="#1E1E2E",
                linewidth=2,
                alpha=0.85
            )
            ax.add_patch(rect)

            # Score label
            ax.text(
                col + 0.5, 4 - row + 0.55,
                str(score),
                ha="center", va="center",
                fontsize=16, fontweight="bold",
                color="white"
            )

            # Zone label
            ax.text(
                col + 0.5, 4 - row + 0.28,
                zone,
                ha="center", va="center",
                fontsize=7, color="white", alpha=0.85
            )

    # Axis labels
    ax.set_xlim(0, 5)
    ax.set_ylim(0, 5)
    ax.set_xticks([i + 0.5 for i in range(5)])
    ax.set_xticklabels(LIKELIHOOD_LABELS, fontsize=9, color="white")
    ax.set_yticks([i + 0.5 for i in range(5)])
    ax.set_yticklabels(reversed(IMPACT_LABELS), fontsize=9, color="white")
    ax.tick_params(colors="white")

    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

    # Axis titles
    ax.set_xlabel("Likelihood", fontsize=12, color="white", labelpad=10)
    ax.set_ylabel("Impact", fontsize=12, color="white", labelpad=10)

    # Chart title
    ax.set_title(
        "AcmeCorp ISO 27001 Risk Heat Map\nLikelihood x Impact Matrix",
        fontsize=14, fontweight="bold", color="white", pad=15
    )

    # Legend
    legend_patches = [
        mpatches.Patch(color=COLOURS[k], label=k)
        for k in ["Critical", "High", "Medium", "Low"]
    ]
    ax.legend(
        handles=legend_patches,
        loc="upper left",
        bbox_to_anchor=(1.02, 1),
        framealpha=0.2,
        labelcolor="white",
        fontsize=10
    )

    plt.tight_layout()
    plt.savefig(HEATMAP_OUT, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"\n[INFO] Heat map saved: {HEATMAP_OUT}")


def generate_brs_chart(df: pd.DataFrame) -> None:
    """
    Generate a BRS distribution bar chart grouped by asset.
    Saved as reports/brs_distribution.png
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#1E1E2E")

    # -- Chart 1: BRS distribution by classification --
    ax1 = axes[0]
    ax1.set_facecolor("#2A2A3E")
    levels = ["Critical", "High", "Medium", "Low"]
    counts = [len(df[df["BRS_Classification"] == l]) for l in levels]
    colors = [COLOURS[l] for l in levels]
    bars   = ax1.bar(levels, counts, color=colors, edgecolor="#1E1E2E", linewidth=1.5, width=0.6)

    for bar, count in zip(bars, counts):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            str(count),
            ha="center", va="bottom",
            fontsize=12, fontweight="bold", color="white"
        )

    ax1.set_title("CVE Count by BRS Classification", color="white", fontsize=12, pad=10)
    ax1.set_ylabel("Number of CVEs", color="white")
    ax1.tick_params(colors="white")
    ax1.set_facecolor("#2A2A3E")
    for spine in ax1.spines.values():
        spine.set_edgecolor("#444")
    ax1.yaxis.label.set_color("white")

    # -- Chart 2: Max BRS per asset --
    ax2 = axes[1]
    ax2.set_facecolor("#2A2A3E")

    asset_max = df.groupby("Asset_Name")["BRS"].max().sort_values(ascending=True)
    bar_colors = [
        COLOURS[classify_brs(v)] for v in asset_max.values
    ]

    short_names = [n.replace("AcmePay ", "").replace(" Environment", "").replace(" Database", " DB")
                   for n in asset_max.index]

    bars2 = ax2.barh(short_names, asset_max.values, color=bar_colors,
                     edgecolor="#1E1E2E", linewidth=1.5, height=0.6)

    for bar, val in zip(bars2, asset_max.values):
        ax2.text(
            val + 0.1,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.1f}",
            va="center", fontsize=10, fontweight="bold", color="white"
        )

    ax2.set_title("Max BRS Score per Asset", color="white", fontsize=12, pad=10)
    ax2.set_xlabel("Business Risk Score (0-10)", color="white")
    ax2.set_xlim(0, 11)
    ax2.tick_params(colors="white")
    ax2.axvline(x=6.0, color="#F4A226", linestyle="--", linewidth=1.5, alpha=0.7, label="Appetite threshold")
    ax2.axvline(x=8.0, color="#D7263D", linestyle="--", linewidth=1.5, alpha=0.7, label="Critical threshold")
    ax2.legend(fontsize=8, labelcolor="white", framealpha=0.2)
    ax2.xaxis.label.set_color("white")
    for spine in ax2.spines.values():
        spine.set_edgecolor("#444")

    fig.suptitle(
        "AcmeCorp SecureGRC -- Business Risk Score Analysis",
        fontsize=14, fontweight="bold", color="white", y=1.01
    )

    plt.tight_layout()
    plt.savefig(BARCHART_OUT, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"[INFO] BRS chart saved: {BARCHART_OUT}")


def classify_brs(brs: float) -> str:
    """BRS classifier -- mirrors vuln_puller.py logic."""
    if brs >= 8.0:   return "Critical"
    elif brs >= 6.0: return "High"
    elif brs >= 4.0: return "Medium"
    return "Low"


def main():
    print("\n[INFO] SecureGRC -- Risk Scorer & Visualisation Engine")
    print("[INFO] Reading from: data/scored_risks.csv")

    # Load data
    df = load_data(CSV_INPUT)

    # Analysis report
    analyse(df)

    # Generate heat map (ISO 27001 matrix)
    generate_heatmap()

    # Generate BRS distribution charts
    generate_brs_chart(df)

    print("\n[INFO] M5 complete. Outputs saved:")
    print(f"  Heat map    : {HEATMAP_OUT}")
    print(f"  BRS chart   : {BARCHART_OUT}")
    print("\n  Run from project root: python automation\\risk_scorer.py\n")


if __name__ == "__main__":
    main()