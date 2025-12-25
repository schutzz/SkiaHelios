# SH_ChronosSift (The Time)
> **"Time is the only true unit of measure."**

[![Part of SkiaHelios](https://img.shields.io/badge/SkiaHelios-Module-blueviolet)](https://github.com/schutzz/SkiaHelios)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Polars](https://img.shields.io/badge/Powered%20by-Polars-orange)](https://www.pola.rs/)

## 👁️ Overview
**SH_ChronosSift** is the "Timekeeper" of the [SkiaHelios](https://github.com/schutzz/SkiaHelios) forensics suite.
It performs high-speed validation of NTFS timestamps (`$STANDARD_INFORMATION` vs `$FILE_NAME`) to detect **Timestomping** and **Backdating** attacks.

Unlike traditional tools that rely on manual filtering, ChronosSift (v9.0) leverages **Polars** to scan millions of records in seconds, creating a comprehensive "Time Anomaly Database" ready to be joined with **SH_PandorasLink** or **SH_ChaosGrasp**.

## ✨ Key Features (v9.0)
* **Polars Engine:** Replaced Pandas with Polars LazyFrame. Analyzing 10 million+ MFT entries takes only seconds.
* **Timestomp Detection:** Automatically flags logically impossible timestamps:
    * **TIMESTOMP_BACKDATE:** `$SI < $FN` (Kernel time is newer than User time).
    * **FALSIFIED_FUTURE:** `$SI > Future` (Future dating).
* **Zero-Precision Check:** Detects timestamps with `000` nanoseconds, a hallmark of crude timestomping tools.
* **Integration Ready:** Generates normalized `Target_FileName` keys to correlate time anomalies with specific "Ghost" files found by Pandora.

## 🚀 Usage

### Requirements
* **Input:** CSVs from Eric Zimmerman's **MFTECmd** (`$MFT`).

### Command
```bash
# Standard Scan (Recommended)
# Scans everything with a 10-second tolerance for standard deviations.
python SH_ChronosSift.py -f "C:\Case\$MFT.csv" -o "chronos_result.csv"

# Strict Mode
# Detects even 1-second deviations (Higher noise, but catches subtle edits)
python SH_ChronosSift.py -f "C:\Case\$MFT.csv" -t 1.0
```

## 📊 Output Schema (`chronos_result.csv`)
| Column | Description |
| :--- | :--- |
| **Anomaly_Time** | Flag: `TIMESTOMP_BACKDATE` or `FALSIFIED_FUTURE`. |
| **Anomaly_Zero** | Flag: `ZERO_PRECISION` (Nanosecond manipulation detected). |
| **FileName** | Name of the file. |
| **SI_Created** | `$STANDARD_INFORMATION` Create Time (User land). |
| **FN_Created** | `$FILE_NAME` Create Time (Kernel land). |

---
*Part of the **SkiaHelios** Ecosystem. "Ex Umbra in Solem".*