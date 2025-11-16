#!/usr/bin/env python3
"""
per_cipher_analysis.py
-----------------------
Performs frequency analysis for each ciphertext file in 'cleaned/' directory.
Outputs:
 - analysis/freq_<filename>.csv
 - analysis/hist_<filename>.png
 - analysis/top_<filename>.txt
"""

import os
import csv
from collections import Counter
import matplotlib.pyplot as plt

# === CONFIG ===
INPUT_DIR = "cleaned"
OUT_DIR = "analysis"
os.makedirs(OUT_DIR, exist_ok=True)

def analyze_ciphertext(file_path):
    name = os.path.basename(file_path).replace(".txt", "")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read().upper()

    # Keep only A-Z
    filtered = "".join(ch for ch in text if 'A' <= ch <= 'Z')
    if not filtered:
        print(f"[!] Skipping {name}: no alphabetic content.")
        return

    freq = Counter(filtered)
    total = sum(freq.values())
    print(f"[*] Analyzing {name} — total letters: {total}")

    # === Save frequency table (CSV) ===
    csv_path = os.path.join(OUT_DIR, f"freq_{name}.csv")
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Letter", "Count", "Relative %"])
        for letter in map(chr, range(65, 91)):
            c = freq.get(letter, 0)
            pct = (c / total) * 100
            writer.writerow([letter, c, f"{pct:.4f}"])
    print(f"    → Saved table: {csv_path}")

    # === Plot histogram ===
    letters = [l for l in map(chr, range(65, 91))]
    rel_perc = [(freq.get(l, 0) / total) * 100 for l in letters]

    plt.figure(figsize=(10,4))
    plt.bar(letters, rel_perc)
    plt.title(f"Letter Frequency: {name}")
    plt.xlabel("Letter")
    plt.ylabel("Frequency (%)")
    plt.grid(axis='y', linestyle=':', alpha=0.6)
    plt.tight_layout()
    hist_path = os.path.join(OUT_DIR, f"hist_{name}.png")
    plt.savefig(hist_path)
    plt.close()
    print(f"    → Saved histogram: {hist_path}")

    # === Save top-letters summary ===
    txt_path = os.path.join(OUT_DIR, f"top_{name}.txt")
    with open(txt_path, "w") as ftxt:
        ftxt.write(f"Top letters by frequency for {name}:\n\n")
        for letter, count in freq.most_common(10):
            pct = (count / total) * 100
            ftxt.write(f"{letter}: {count} ({pct:.2f}%)\n")

        ftxt.write("\nSuggested mappings (based on English frequency):\n")
        english_top = "ETAOINSHRDLU"
        for i, (letter, _) in enumerate(freq.most_common(len(english_top))):
            ftxt.write(f"{letter} → {english_top[i]}\n")

    print(f"    → Saved top-letters summary: {txt_path}\n")


# === MAIN ===
def main():
    if not os.path.exists(INPUT_DIR):
        print(f"Error: {INPUT_DIR}/ not found. Run your cleaning step first.")
        return

    files = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(".txt")])
    if not filesOB:
        print(f"Noot os.path.exists(INPUT_DIR): cleaned ciphertexts found in {INPUT_DIR}/")
        return

    for file in files:
        analyze_ciphertext(os.path.join(INPUT_DIR, file))

    print("\n✅ Analysis complete! All results saved in 'analysis/' folder.\n")

if __name__ == "__main__":
    main()
