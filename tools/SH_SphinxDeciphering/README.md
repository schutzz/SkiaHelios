# SH_SphinxDeciphering (The Riddle)
> **"Answer my riddle, or be consumed."**

[![Part of SkiaHelios](https://img.shields.io/badge/SkiaHelios-Module-blueviolet)](https://github.com/schutzz/SkiaHelios)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Polars](https://img.shields.io/badge/Powered%20by-Polars-orange)](https://www.pola.rs/)

## 👁️ Overview
**SH_SphinxDeciphering** is the "Cryptanalyst" of the [SkiaHelios](https://github.com/schutzz/SkiaHelios) forensics suite.
It specializes in detecting and de-obfuscating malicious PowerShell scripts found in Event Logs (Event ID 4104).

Unlike traditional keyword searching, Sphinx uses **Physical Characteristics** (Entropy, Symbol Density, Length) to detect obfuscation that bypasses AV signatures. It then automatically "peels" the layers of obfuscation to reveal the original intent.

## ✨ Key Features (v0.3 Verified)
* **KAPE/EvtxECmd Ready:** Automatically detects and parses CSV exports from KAPE or generic JSON (ndjson) log dumps.
* **Physical Detection:** Flags scripts based on "Physics" rather than just keywords:
    * **High Entropy:** Detects randomized variable names and encrypted payloads.
    * **Symbol Density:** Detects obfuscation using excessive concatenation (`+`) or backticks (`` ` ``).
* **Auto-Deobfuscation (Peeling):**
    * **Level 1:** Recursive Base64 decoding.
    * **Level 2:** String manipulation reversal (Concatenation & Backticks removal).
    * *Example:* `&('I'+'E'+'X')` -> `&(IEX)`
* **Risk Scoring:** Assigns a numerical risk score (0-100+) based on multiple factors, prioritizing the "Most Likely Malicious" scripts at the top.

## 🚀 Usage

### Requirements
* **Input:** CSVs from KAPE (**EvtxECmd**) or JSON exports.

### Command
```bash
# Analyze a KAPE output CSV
python SH_SphinxDeciphering.py -f "C:\Case\KAPE_Output\FileSystem\EvtxECmd_Output.csv" -o "sphinx_report.csv"

# Analyze a raw JSON dump
python SH_SphinxDeciphering.py -f "C:\Case\logs.json"
```

## 📊 Output Schema (`sphinx_result.csv`)

| Column | Description |
| :--- | :--- |
| **Risk_Score** | The calculated maliciousness score. Higher is worse. |
| **Tags** | Detection reasons (e.g., `HIGH_ENTROPY`, `OBFUSCATION_PEELED`). |
| **Peeled_Snippet** | **The Truth.** The script content after removing backticks and concatenation. |
| **Decoded_Hint** | Any Base64 strings found and decoded from within the script. |
| **Original_Snippet** | The raw, obfuscated log content (for reference). |

---
*Part of the **SkiaHelios** Ecosystem. "Ex Umbra in Solem".*