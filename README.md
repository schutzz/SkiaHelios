# SkiaHelios v1.9 - God Mode (The Chimera Edition)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Polars](https://img.shields.io/badge/Engine-Polars_0.20%2B-orange?logo=polars)
![Status](https://img.shields.io/badge/Status-Battle_Tested-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> *"From Shadows to Sun. Order restored. Truth revealed."*

**SkiaHelios** is a high-resolution, modular DFIR (Digital Forensics & Incident Response) framework built for **speed** and **causality**. Unlike traditional monolithic tools, it uses a specialized **"Triad Architecture" (Clotho-Atropos-Lachesis)** to deconstruct artifacts, trace physical execution chains, and weave a cohesive narrative across multiple hosts.

**Current Version:** v1.9 (Chimera Fusion / Lateral Movement Aware)

---

## ⚡ Key Features (Why SkiaHelios?)

* **🚀 Hyperspeed Ingestion:** Powered by **Polars (Rust-based DataFrame library)** to handle massive CSV timelines (KAPE/Plaso) instantly.
* **🦁 Operation Chimera (Multi-Host):** **New in v1.9!** Seamlessly integrates timelines from multiple compromised hosts (`SH_ChimeraFusion`) to visualize Lateral Movement chains.
* **🔮 Physics-Based Detection:**
    * **Chronos:** Detects NTFS Timestomping via `$SI < $FN` logic (ms precision).
    * **Plutos:** Analyzes "Network Thermodynamics" (Heat Score) to find data exfiltration and internal lateral movement.
    * **Atropos:** Correlates "Execution" with "File Drops" to prove causality (not just existence).
* **🛡️ Noise Cancellation:** Aggressive "Iron Curtain" filtering logic to remove OS noise (WinSxS, .NET, Updates) and focus on the 1% of critical anomalies.

---

## 🧪 Validation & Benchmarks (Proven Capability)

SkiaHelios is not just a concept. It is validated against complex attack scenarios.

### 🏆 Operation "TwinSnakes" (Lateral Movement Scenario)
**Status:** ✅ **PASSED (S-Rank)**
* **Scenario:** Phishing Entry (Host A) → Persistence → Lateral Movement (PsExec) → Target Access (Host B) → Timestomping & Exfiltration.
* **Result:**
    * Detected **100%** of attack phases.
    * **Automatic Correlation:** Identified the attack flow across 2 distinct hosts without manual timeline merging.
    * **Verdict:** Correctly flagged `[LATERAL_MOVEMENT_CONFIRMED]` and pinpointed `Conf.7z` (Timestomped Archive).

### ⚔️ Atomic Red Team (Infect28 / SunShadow)
**Status:** ✅ **PASSED**
* **Vectors Detected:**
    * PowerShell Obfuscation (Base64/XOR) via `SH_Sphinx`.
    * Persistence (Registry RunKeys, Scheduled Tasks) via `SH_AION`.
    * Data Exfiltration (OneDrive/Bitsadmin) via `SH_Plutos`.

---

## 🏛️ Architecture (The Triad)

SkiaHelios separates concerns into three divine roles to ensure modularity and logic isolation.

```mermaid
graph TD
    %% Input
    Evidence[Raw Artifacts / KAPE CSVs] --> Clotho

    %% Phase 1: Ingest
    subgraph "Phase 1: Clotho (The Spinner)"
        Clotho[SH_ClothoReader] -->|Normalize & Enrich| DataFrame[(Polars DataFrame)]
        Modules[Plutos / Pandora / AION / Hercules] -.-> Clotho
    end

    %% Phase 2: Logic
    subgraph "Phase 2: Atropos (The Thinker)"
        DataFrame --> Atropos[SH_AtroposThinker]
        Atropos --> Nemesis{Nemesis Engine}
        Atropos --> Chronos{Chronos Time Lord}
        Atropos --> InternalScout{Lateral Scout}
    end

    %% Phase 3: Output
    subgraph "Phase 3: Lachesis (The Allotter)"
        Atropos --> Lachesis[SH_LachesisWriter]
        Lachesis --> Report[Grimoire Report (.md)]
        Lachesis --> JSON[Grimoire Data (.json)]
    end

    %% Phase 4: Fusion
    subgraph "Phase 4: Chimera (The Beast)"
        JSON --> Chimera[SH_ChimeraFusion]
        Chimera --> CampaignReport[Campaign Report (.md)]
    end
```

---

## 🛠️ Installation

```bash
# Clone the repository
git clone [https://github.com/schutzz/SkiaHelios.git](https://github.com/schutzz/SkiaHelios.git)
cd SkiaHelios

# Install dependencies (Polars is the only heavy requirement)
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1. Full Auto Scan (Single Host)
The `SH_HeliosConsole.py` acts as the commander, running all modules in sequence.

```bash
python SH_HeliosConsole.py \
  --dir "C:\Case\KAPE_Output\HostA" \
  --case "Incident_Alpha_HostA" \
  --out "Helios_Output"
```

### 2. Manual Triad Execution (Granular Control)
For advanced analysts who want to debug specific logic steps.

```bash
# Step 1: Run specialized detectors
python tools/SH_AIONDetector.py --dir "KAPE/" --out "Persistence.csv"
python tools/SH_PlutosGate.py --dir "KAPE/" --out "Network.csv"

# Step 2: Weave the Grimoire (Report)
python tools/SH_HekateWeaver.py \
  -i "KAPE/Timeline.csv" \
  -o "Reports/HostA_Grimoire.md" \
  --aion "Persistence.csv" \
  --plutos "Network.csv" \
  --case "Manual_Analysis"
```

### 3. Operation Chimera (Multi-Host Fusion)
Combine reports from multiple hosts to visualize the entire campaign.

```bash
# Point to the directory containing multiple Grimoire_*.json files
python tools/SH_ChimeraFusion.py \
  -d "Helios_Output/" \
  -o "Helios_Output/Campaign_Master_Report.md"
```

---

## 🧩 Module Breakdown

| Module | Role | Functionality |
| :--- | :--- | :--- |
| **Hercules** | The Referee | Event Log analysis, Identity tracking (SID resolution), and initial triage. |
| **Plutos** | Gatekeeper | Network & SRUM analysis. Detects C2, Lateral Movement, and Data Exfiltration using "Heat Scores". |
| **Pandora** | The Link | NTFS/USN analysis. Recovers deleted file history ("Ghosts") and anti-forensics traces. |
| **Chronos** | Time Lord | Detects **Timestomping** by comparing `$SI` and `$FN` attributes with ms-level precision. |
| **AION** | The Eye | Persistence hunting (Registry, Tasks, Services). Calculates SHA256 for evidence. |
| **Sphinx** | Decipherer | Decodes obfuscated command lines (Base64, PowerShell) and extracts IOCs. |
| **Siren** | Validator | Cross-validates file events with **Prefetch** & **Amcache** to confirm execution. |

---

## 🔮 Roadmap
* [x] **v1.9:** Internal Scout & Lateral Movement Logic (Completed)
* [x] **v1.9:** Chimera Fusion (Multi-Host Reporting) (Completed)
* [ ] **v2.0:** GUI / Web Dashboard (React based)
* [ ] **v2.1:** SIGMA Rule Integration

---
*Created by the SkiaHelios Team. Powered by Polars.*