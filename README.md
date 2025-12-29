# SkiaHelios: Advanced DFIR Artifact Correlation Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-win)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Precision_God_Mode-red)

**"Truth is a multi-layered tapestry. Weave it."**

SkiaHelios is a modular Digital Forensics & Incident Response (DFIR) framework designed to correlate disparate artifacts (Timeline, Registry, Network, USN Journal, SRUM) into a single, cohesive narrative. SkiaHelios reconstructs the *context* of user activity and generates professional, SANS-style investigation reports automatically.

**Current Version:** v17.0 (Core) / v15.37 (Hekate) / v4.0 (Console)

---

## ⚡ Key Features (v17 Update)

* **🛡️ Precision Over Recall (適合率重視):**
    * 厳格なスコアリングロジックにより、正規プロセス（LOLBins）やWindows Updateの残骸などのノイズを徹底排除。
    * **"Criticality >= 90"** の確実な脅威のみを技術詳細に記載。
* **📝 Dynamic Attack Flow Generation:**
    * イベントカテゴリを解析し、攻撃のストーリーラインをExecutive Summaryに自動生成。
* **🦁 Sphinx v1.9 Integration:**
    * PowerShell (4104) / Process (4688) のBase64難読化を自動解除し、相対パス実行も検知。
* **🕸️ Nemesis Lifecycle Tracing:**
    * MFT/USNから「ファイルの誕生・変名・削除」を芋づる式に完全復元。

---

## 🧩 Architecture: The Cerberus Pipeline

```mermaid
graph TD
    %% === 1. Ingestion Layer ===
    subgraph Ingestion["🔍 Evidence Ingestion (KAPE Modules)"]
        direction LR
        MFT["MFT / USN Journal"] -->|Timeline| Chaos
        Reg[Registry] -->|Persistence| AION
        Evtx["Event Logs\n(Security, PowerShell, Sysmon)"] -->|Execution| Sphinx
        Net["Network / SRUM"] -->|Exfil| Plutos
    end

    %% === 2. Core Processing ===
    Chaos["🌪️ ChaosGrasp\nMaster Timeline Builder"] 
    Sphinx["🦁 Sphinx v1.7\nDeobfuscation & Seed Extraction"]
    AION["👁️ AIONDetector\nPersistence Scanner"]
    Plutos["💀 PlutosGate\nNetwork & Exfil Analysis"]
    Pandora["📦 Pandora\nGhost File Recovery"]

    %% === 3. Correlation Engine ===
    subgraph Correlation["⚔️ Nemesis Correlation Engine"]
        direction TB
        Nemesis["⛓️ NemesisTracer\nLifecycle Reconstruction\n(Birth → Rename → Execution → Death)"]
        Hercules["🏛️ HerculesReferee\nHigh-Precision Judgment\n(Criticality Scoring)"]
    end

    %% === 4. Final Weaver ===
    Hekate["🕸️ HekateWeaver v15.32\nPrecision Filter & Report Generator"]

    %% === Flow ===
    Ingestion --> Chaos
    Chaos --> Sphinx & AION & Plutos & Pandora
    Sphinx -->|Extracted Seeds| Nemesis
    Pandora -->|Recovered Paths| Nemesis
    AION & Plutos -->|Artifacts| Nemesis
    Nemesis -->|Enriched Events| Hercules
    Hercules -->|Validated Timeline| Hekate
    Hekate --> Report[(📜 Grimoire Report\nSANS-Grade Markdown)]

    %% === Styling ===
    classDef ingestion fill:#2a2a2a,stroke:#555,color:#fff
    classDef core fill:#1a365d,stroke:#2c5282,color:#fff
    classDef correlation fill:#4a148c,stroke:#7e22ce,color:#fff
    classDef output fill:#1e40af,stroke:#2563eb,color:#fff,font-weight:bold

    class MFT,Reg,Evtx,Net ingestion
    class Chaos,Sphinx,AION,Plutos,Pandora core
    class Nemesis,Hercules correlation
    class Hekate,Report output
```

---

## 🚀 Usage

### 1. Prerequisites
```bash
pip install -r requirements.txt
```

### 2. Execution (Helios Console v4.0)
```powershell
python SH_HeliosConsole.py --dir "C:\Case\KAPE_CSV" --raw "C:\Case\Raw_Artifacts" --start 2025-12-01 --end 2025-12-31
```

**Arguments:**
* `--dir`: Path to KAPE module outputs (CSV files).
* `--raw`: Path to KAPE targets (Raw artifacts).
* `--mount`: (Optional) Mount Point for SHA256 hashing.
* `--start / --end`: (Optional) Time filter (YYYY-MM-DD).

### 3. Output (The Grimoire)
The **`Grimoire_[CaseName]_[Lang].md`** provides:
* **Executive Summary:** Attack flow and compromised accounts.
* **Timeline:** Phase-based chronological narrative.
* **Technical Findings:** Validated evidence (Score >= 90).

---

## 🛠️ Modules Overview

| Module | Role | Key Function |
| :--- | :--- | :--- |
| **SH_HeliosConsole** | Orchestrator | Pipeline & Timekeeper management. |
| **SH_HekateWeaver** | Weaver | Noise filtering & Grimoire generation. |
| **SH_HerculesReferee**| Judge | Sniper scanning & Verdict execution. |
| **SH_SphinxDeciphering**| Decoder | PowerShell/Process deobfuscation. |
| **SH_AIONDetector** | Persistence | Registry & Startup folder scanning. |
| **SH_PandorasLink** | Recovery | Deleted file (Ghost) identification. |
| **SH_ChronosSift** | Anti-Forensics | Timestomp anomaly detection. |
| **SH_PlutosGate** | Network | SRUM & C2 beacon analysis. |

---

> *"Non-rational thinking is a vice; rational thinking is a virtue."*
