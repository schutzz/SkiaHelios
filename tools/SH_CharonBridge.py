import yaml
import re
import argparse
from pathlib import Path

# ============================================================
#  SH_CharonBridge v1.0 [AION Protocol]
#  Mission: Ferryman of Sigma Rules into Themis Laws.
#  Philosophy: Transcode abstract logic to Regex Microcode.
# ============================================================

class CharonBridge:
    def __init__(self):
        # [Signal Mapping]
        # Sigmaの抽象フィールドを、AIONの物理カラム(Schema)に配線するっス
        self.field_map = {
            # Process Creation / Command Line
            "Image": "Target_Path",          # フルパス or プロセス名
            "CommandLine": "Target_Path",    # コマンドライン引数含む
            "ParentImage": "ParentPath",     # 親プロセス
            
            # File System
            "TargetFilename": "Target_FileName",
            "OriginalFileName": "FileName",
            
            # Context
            "CurrentDirectory": "Full_Path",
            "User": "User",
            "Service": "Services",           # Registry Service Name
            
            # Registry
            "TargetObject": "Full_Path",     # Registry Key Path
        }
        
        # [Voltage Level Mapping]
        # Sigmaの深刻度をAIONのThreat Scoreへ変換
        self.score_map = {
            "critical": 100,
            "high": 80,
            "medium": 50,
            "low": 20,
            "informational": 0
        }

    def _compile_regex(self, value):
        """
        Sigmaのワイルドカードやリスト構造を
        Rust/Polars互換の高速Regexパターンにコンパイルするっス。
        """
        if isinstance(value, list):
            # リストは論理和(OR)として並列回路化
            # [cmd, powershell] -> (?i)(cmd|powershell)
            sanitized = [re.escape(str(v)).replace(r"\*", ".*").replace(r"\?", ".") for v in value]
            return f"(?i)({'|'.join(sanitized)})"
        
        elif isinstance(value, str):
            # ワイルドカードをRegexへ置換
            # *evil* -> .*evil.*
            pattern = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
            return f"(?i){pattern}"
        
        return str(value)

    def _parse_detection_logic(self, detection):
        """
        Sigmaのdetectionブロック(AST)を解析し、AIONが実行可能な単純命令セットに分解する。
        現在は 'selection' 系のポジティブマッチのみを抽出して論理積(AND)を構成。
        """
        if not detection: return []

        # 1. 抽出対象のブロックを特定 (condition, timeframe以外)
        # 複雑な条件式 (1 of them, all of them) は、今回は「出現した条件すべて」を
        # 個別の検知ルールとしてフラット化して扱う（False Positive上等で取りこぼしを防ぐ戦略）
        target_blocks = [v for k, v in detection.items() if k not in ["condition", "timeframe"]]
        
        extracted_rules = []

        for block in target_blocks:
            # 辞書型 (Field: Value) の場合 -> 特定カラムへのマッチング
            if isinstance(block, dict):
                for field, value in block.items():
                    # 修飾子(Modifier)の処理 (e.g., Image|endswith)
                    parts = field.split("|")
                    base_field = parts[0]
                    modifier = parts[1] if len(parts) > 1 else "regex"
                    
                    # カラムマッピング解決
                    target_col = self.field_map.get(base_field, "Full_Path") # マッピング不能なら全体検索
                    
                    # パターンコンパイル
                    pattern = self._compile_regex(value)
                    
                    # Modifierに応じた微調整（基本はRegexで吸収するが、明示的な場合）
                    if modifier == "contains":
                        pass # Regexのデフォルト動作
                    elif modifier == "startswith":
                        pattern = f"^{pattern[4:]}" if pattern.startswith("(?i)") else f"^{pattern}"
                    elif modifier == "endswith":
                        pattern = f"{pattern}$"

                    extracted_rules.append({
                        "target": target_col,
                        "condition": "regex",
                        "pattern": pattern
                    })
            
            # リスト型 (Keywords) の場合 -> 全文検索
            elif isinstance(block, list):
                pattern = self._compile_regex(block)
                extracted_rules.append({
                    "target": "Full_Path",
                    "condition": "regex",
                    "pattern": pattern
                })

        return extracted_rules

    def ferry(self, sigma_path):
        """
        Sigmaファイルを読み込み、AIONルールオブジェクトを生成して運ぶっス。
        """
        try:
            with open(sigma_path, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"[!] Charon Stumbled: {sigma_path} ({e})")
            return []

        ferried_rules = []
        for doc in docs:
            if not doc: continue
            
            title = doc.get("title", "Unknown Rule")
            level = doc.get("level", "medium")
            tags = doc.get("tags", [])
            logsource = doc.get("logsource", {})
            detection = doc.get("detection", {})
            status = doc.get("status", "")

            # [修正後] experimental（実験中）と deprecated（廃止）だけ弾く！
            # test（検証中）と stable（安定）は通す！
            if status == "experimental" or status == "deprecated" or status == "unsupported":
                continue

            # 対象OSフィルタリング
            product = logsource.get("product", "").lower()
            if product and "windows" not in product:
                continue

            # ルール変換実行
            conditions = self._parse_detection_logic(detection)
            
            # 1つのSigmaルールから生成された条件を、Themis用の独立したルールエントリに変換
            # ※ 本来はAND条件だが、AIONの初期実装では「いずれかにヒットしたらタグ付け」で広めに拾う
            for cond in conditions:
                rule_entry = {
                    "name": f"[Sigma] {title}",
                    "tag": ",".join(tags) if tags else "SIGMA_IMPORT",
                    "score": self.score_map.get(level, 50),
                    "target": cond["target"],
                    "condition": cond["condition"],
                    "pattern": cond["pattern"]
                }
                ferried_rules.append(rule_entry)

        return ferried_rules

    def execute(self, sigma_dir, output_file):
        print(f"[*] CharonBridge: Crossing the river to '{sigma_dir}'...")
        path = Path(sigma_dir)
        all_rules = []
        
        # 再帰的に探索
        files = list(path.rglob("*.yml")) + list(path.rglob("*.yaml"))
        print(f"[*] Found {len(files)} souls (Sigma files).")

        for p in files:
            rules = self.ferry(p)
            all_rules.extend(rules)

        # Themisが読み込める形式で出力
        output_data = {
            "#": f"Imported by SH_CharonBridge on {path.name}",
            "threat_signatures": all_rules,
            "noise_filters": [] # Sigmaは基本「検知」なのでNoiseは空
        }

        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(output_data, f, sort_keys=False, allow_unicode=True)
        
        print(f"[+] Arrival: {len(all_rules)} rules delivered to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="CharonBridge: Sigma to AION Converter")
    parser.add_argument("sigma_dir", help="Source directory of Sigma rules")
    parser.add_argument("-o", "--out", default="rules/sigma_imported.yaml", help="Destination YAML")
    args = parser.parse_args()

    bridge = CharonBridge()
    bridge.execute(args.sigma_dir, args.out)

if __name__ == "__main__":
    main()