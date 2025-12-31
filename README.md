# SkiaHelios v2.2 - God Mode (Visual & Legacy Edition)

![SkiaHelios CI](https://github.com/schutzz/SkiaHelios/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Polars](https://img.shields.io/badge/Engine-Polars_0.20%2B-orange?logo=polars)
![Mermaid](https://img.shields.io/badge/Report-Mermaid_Visuals-ff69b4?logo=mermaid)
![Status](https://img.shields.io/badge/Status-Battle_Tested-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> *"From Shadows to Sun. Order restored. Truth visualized."*

**SkiaHelios** is a high-resolution, modular DFIR (Digital Forensics & Incident Response) framework built for **speed**, **causality**, and **visual narrative**.

Unlike traditional monolithic tools that dump raw text, SkiaHelios uses a specialized **"Triad Architecture" (Clotho-Atropos-Lachesis)** to deconstruct artifacts, trace physical execution chains, and weave a cohesive narrative across multiple hosts.

**Current Version:** v2.2 (Visual Reporting / Legacy OS Support / Interactive Mode / Chimera Fusion)

---

## ⚡ Key Features (v2.2 Updates)

* **🏹 Visual Attack Flow:** Automatically generates **Mermaid diagrams** visualizing the attack chain (Initial Access -> Execution -> Persistence).
* **🕰️ Hybrid Time Logic:** Specialized **`--legacy` mode** for older OS environments (XP/Vista/2008) to eliminate install-time noise vs. Modern OS optimization.
* **👻 Ghost Hunting & Threat Intel:** Recovers deleted files (`$UsnJrnl` vs `$MFT`) and detects **WebShells (c99, r57)**, **Rootkits**, and **C2 IP traces** with heavy weighting.
* **💎 High-Value IOCs:** Aggregates scattered indicators into a clean, actionable table at the top of the report.
* **🦁 Interactive Wizard:** No command memorization needed. Just run and follow the prompts.
* **🔥 Chimera Fusion:** Correlates Lateral Movement across multiple hosts to visualize the entire campaign.

---

## ⚡ Quick Start (30 Seconds)

Get started immediately. No complex databases, just pure Python & Polars power.

### 1. Installation
```bash
# Clone the repository
git clone [https://github.com/schutzz/SkiaHelios.git](https://github.com/schutzz/SkiaHelios.git)
cd SkiaHelios

# Install dependencies (Polars, Pandas, etc.)
pip install -r requirements.txt
```

### 2. Interactive Mode (Wizard) 🆕
Simply run the script without arguments. It will guide you through directory selection and mode toggling.

```bash
python SH_HeliosConsole.py
# Follow the prompts to select Input Dir, Output Dir, and Legacy Mode.
```

### 3. Command Line Mode (Automation)
Ideal for CI/CD pipelines or scripted analysis.

**Standard Scan (Modern OS - Win10/11/Server 2016+):**
```bash
python SH_HeliosConsole.py \
  --dir "C:\Cases\Case_001\KAPE_Output" \
  --case "Ransomware_Investigation"
```

**Legacy Scan (Old OS - XP/Vista/2008/2012 or High Noise):**
*Use this flag to ignore System32/Program Files timestamps and focus on User/Web spaces.*
```bash
python SH_HeliosConsole.py \
  --dir "C:\Cases\GrrCON_2014\KAPE_Output" \
  --case "Legacy_Breach" \
  --legacy
```

### 4. Operation Chimera (Multi-Host Fusion)
Combine reports from multiple hosts to visualize the entire campaign.

```bash
# Point to the directory containing multiple Grimoire_*.json files
python tools/SH_ChimeraFusion.py \
  -d "Helios_Output/" \
  -o "Helios_Output/Campaign_Master_Report.md"
```

---

## 🧩 The Triad Architecture

SkiaHelios operates on three distinct layers of abstraction:

### 🧵 1. Clotho (The Spinner)
*Parses raw artifacts into structured DataFrames.*
* **Clio:** Browser History & Cache parser.
* **Pandora:** **[UPDATED]** NTFS/USN analysis. Recovers deleted file history ("Ghosts") and applies Threat Intelligence (WebShell/Rootkit detection).

### 📐 2. Atropos (The Judge)
*Measures, filters, and correlates events.*
* **Chronos:** **[UPDATED]** Hybrid Time Logic. Detects **Timestomping** ($SI < $FN) with ms-level precision. Adapts to Legacy OS.
* **Hercules:** Event Log analysis, Identity tracking (SID resolution), and initial triage.
* **Plutos:** Network & SRUM analysis. Detects C2, Lateral Movement, and Data Exfiltration using "Heat Scores".
* **AION:** Persistence hunting (Registry, Tasks, Services). Calculates SHA256 for evidence.
* **Siren:** Cross-validates file events with **Prefetch** & **Amcache** to confirm execution.

### 🧶 3. Lachesis (The Weaver)
*Weaves the verdict into a human-readable narrative.*
* **Lachesis Engine:** **[UPDATED]** Generates **Visual Reports** with Mermaid charts, IOC tables, and noise folding (`<details>`).
* **Sphinx:** Decodes obfuscated command lines (Base64, PowerShell) and extracts IOCs.

---

## 📊 Report Sample (Grimoire)

SkiaHelios generates a `Grimoire_[CaseName]_jp.md` that renders beautifully in VS Code or GitHub.

```mermaid
graph TD
    %% Nodes Definition
    Attacker((🦁 Attacker)) -->|Exploit/Access| Initial{Initial Access}
    Initial -->|File Upload| WS_12345["c99.php<br/>(WebShell)"]
    WS_12345 -->|Command Exec| Cmd_9999((OS Shell))
    Cmd_9999 -->|Persistence| RK_5555["mxdwdui.BUD<br/>(Rootkit)"]
    
    %% Styles
    classDef threat fill:#ffcccc,stroke:#ff0000,stroke-width:2px,color:#000;
    class Attacker,Initial threat;
```

---

## 🔮 Roadmap

* [x] **v1.0:** Core Logic (Clotho/Atropos/Lachesis)
* [x] **v1.9:** Internal Scout & Lateral Movement Logic (Chimera)
* [x] **v2.0:** **Visual Reporting (Mermaid Integration)**
* [x] **v2.1:** **Legacy OS Support & Threat Intelligence**
* [x] **v2.2:** **Interactive Mode & Syntax Guards**
* [ ] **v2.5:** Volatility 3 Integration (Memory Forensics)
* [ ] **v3.0:** AI-Driven Narrative Generation (LLM Integration)

---

## 🛡️ License

MIT License - Built for the Defenders.