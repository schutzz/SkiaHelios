# 🦁 AION-Sigma Integration Guide (AION-Sigma 統合ガイド)

**The bridge between Global Threat Intelligence and AION's Physical Engine.**
*(世界標準の脅威インテリジェンスと、AIONの物理エンジンを繋ぐ架け橋)*

---

## 📖 Overview (概要)

SkiaHelios v2.7 introduces the **AION-Sigma Pipeline**. This allows you to import **Sigma Rules** (standard YAML format for threat detection) directly into AION's detection engine (`Hercules`, `Pandora`, `Chronos`).

SkiaHelios v2.7 では、**AION-Sigma パイプライン** が導入されました。これにより、**Sigmaルール**（脅威検知の標準フォーマット）を AION の検知エンジン（Hercules, Pandora, Chronos）に直接取り込むことが可能です。

### 🏗️ Architecture (アーキテクチャ)

1.  **Sigma Repository**: Source of truth (YAML files).
2.  **SH_CharonBridge**: The converter. Translates Sigma YAML into AION Regex Rules (`sigma_*.yaml`).
3.  **SH_ThemisLoader**: The intelligence core. Loads these rules into memory and feeds them to analysis modules.

1.  **Sigma リポジトリ**: ルールの源泉（YAMLファイル群）。
2.  **SH_CharonBridge**: コンバータ。Sigma YAML を AION 用の正規表現ルール（`sigma_*.yaml`）に変換します。
3.  **SH_ThemisLoader**: インテリジェンス・コア。変換されたルールをメモリにロードし、各解析モジュールに供給します。

---

## 🛠️ Step-by-Step Setup (セットアップ手順)

### 1. Clone Sigma Repository (Sigmaルールの取得)

First, clone the official Sigma repository (or your private fork) into the SkiaHelios directory.
まず、Sigmaの公式リポジトリ（または独自のフォーク）を SkiaHelios ディレクトリ内にクローンします。

```bash
# In SkiaHelios root directory
git clone [https://github.com/SigmaHQ/sigma.git](https://github.com/SigmaHQ/sigma.git)
```

### 2. Convert Rules via CharonBridge (ルールの変換)

Use `SH_CharonBridge.py` to convert specific Sigma categories into AION-compatible rule files.
`SH_CharonBridge.py` を使用して、特定の Sigma カテゴリを AION 互換のルールファイルに変換します。

#### 🔹 A. Process Creation Rules (For Hercules & Chronos)
**Target:** Detects suspicious commands, LOLBINs, and process trees.
**対象:** 不審なコマンド実行、LOLBINs、プロセスツリーの検知。

```powershell
python tools/SH_CharonBridge.py sigma/rules/windows/process_creation/ -o rules/sigma_process_creation.yaml
```

#### 🔹 B. File Event Rules (For Pandora & Chronos)
**Target:** Detects malware drops, webshell creation, and suspicious file modifications.
**対象:** マルウェアの設置、WebShellの作成、不審なファイル変更の検知。

```powershell
python tools/SH_CharonBridge.py sigma/rules/windows/file/ -o rules/sigma_file_event.yaml
```

#### 🔹 C. Registry Event Rules (For AION Core & Hercules)
**Target:** Detects persistence mechanisms (RunKeys) and configuration tampering.
**対象:** 永続化設定（RunKeys）や設定改ざんの検知。

```powershell
python tools/SH_CharonBridge.py sigma/rules/windows/registry/ -o rules/sigma_registry.yaml
```

> **Note:** You can convert other categories (e.g., `network_connection`) using the same syntax if needed.
> **注記:** 必要であれば、他のカテゴリ（`network_connection` など）も同様の構文で変換可能です。

### 3. Verify Integration (統合の確認)

Run any AION tool (e.g., HeliosConsole). Watch the initialization logs for "Loaded sigma_*.yaml".
AION ツール（HeliosConsole など）を実行し、起動ログに "Loaded sigma_*.yaml" が表示されるか確認してください。

```text
[*] Initializing Engine with Themis Rules...
   > Loaded triage_rules.yaml: 29 rules.
   > Loaded sigma_process_creation.yaml: 3097 rules.  <-- Success!
   > Loaded sigma_file_event.yaml: 474 rules.         <-- Success!
   > Loaded sigma_registry.yaml: 870 rules.           <-- Success!
```

---

## ⚙️ Configuration & Tuning (設定とチューニング)

### 🛡️ Noise Filtering (ノイズ除去)

Sigma rules can generate false positives (FP). Control them using `rules/triage_rules.yaml`.
**AION prioritizes Noise Filters over Sigma Rules** (unless the threat score is Critical).

Sigmaルールは誤検知（FP）を生むことがあります。`rules/triage_rules.yaml` でこれを制御します。
**AION は Sigma ルールよりもノイズフィルタを優先します**（ただし、脅威スコアが Critical の場合を除く）。

**Example: Ignoring a specific noisy folder (ノイズフォルダの除外例):**

```yaml
# rules/triage_rules.yaml

noise_filters:
  - name: "Ignore My Music Folder"
    target: "ParentPath"
    condition: "regex"
    pattern: "(?i)\\\\My Music"
```

### 🎯 Threshold Adjustment (閾値の調整)

To change the sensitivity, modify `SH_PandorasLink.py` or `SH_ChronosSift.py`.
Currently, the strict threshold is set to **Score >= 80**.

感度を変更するには、`SH_PandorasLink.py` または `SH_ChronosSift.py` を編集します。
現在、厳格な閾値として **Score >= 80** が設定されています。

```python
# Only alert if score is High (80) or Critical (100)
df.filter(pl.col("Threat_Score") >= 80)
```

---

## ❓ Troubleshooting (トラブルシューティング)

### Q1. "Found 0 souls" during conversion? (変換時に 0件になる)
* **Check Path:** Ensure the Sigma directory structure hasn't changed. (e.g., is it `file` or `file_event`?)
* **Check Status:** CharonBridge skips `deprecated` and `unsupported` rules by default. Ensure your target rules are `stable` or `test`.
* **パス確認:** Sigmaのディレクトリ構造が変わっていないか確認してください（例: `file` か `file_event` か？）。
* **ステータス確認:** CharonBridge はデフォルトで `deprecated` や `unsupported` なルールをスキップします。対象ルールが `stable` または `test` であるか確認してください。

### Q2. Too many False Positives? (誤検知が多すぎる)
* **Update Triage Rules:** Add the noisy path or filename to `rules/triage_rules.yaml`.
* **Triage更新:** ノイズとなっているパスやファイル名を `rules/triage_rules.yaml` に追加してください。

### Q3. Report is empty? (レポートが空っぽ)
* **Check Statistics:** Check the "Detection Statistics" section in the report. Low-confidence events might be aggregated there.
* **統計を確認:** レポートの「Detection Statistics」セクションを確認してください。低確度のイベントはそこに集約されている可能性があります。

---

*Documentation by SkiaHelios Team*