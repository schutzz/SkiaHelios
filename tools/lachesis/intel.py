import re
import yaml
from pathlib import Path
from tools.SH_ThemisLoader import ThemisLoader

TEXT_RES = {
    "en": {
        "title": "Incident Investigation Report",
        "coc_header": "Chain of Custody & Case Information",
        "h1_exec": "1. Executive Summary",
        "h1_origin": "2. Initial Access Vector Analysis",
        "h1_time": "3. Investigation Timeline (Critical Chain)",
        "h1_tech": "4. Technical Findings (High Confidence)",
        "h1_stats": "5. Detection Statistics",
        "h1_rec": "6. Conclusions & Recommendations",
        "h1_app": "7. Appendix (Critical IOCs Only)",
        "cats": {"INIT": "Initial Access", "C2": "C2 Communication", "PERSIST": "Persistence", "ANTI": "Anti-Forensics", "EXEC": "Execution", "DROP": "File Creation", "WEB": "Web Access"},
        # Executive Summary
        "conclusion_paradox": "**Conclusion:**\nDuring the period of {time_range}, **significant compromise activity with advanced evasion techniques** was confirmed on host {hostname}.\n\n⚠️🚨 **SYSTEM TIME MANIPULATION DETECTED** 🚨⚠️\n**System clock rollback (Time Paradox)** has been detected. The attacker manipulated the system clock to obstruct forensic investigation and intentionally corrupt the log timeline. Extreme caution is required when analyzing the timeline.\n",
        "conclusion_anti": "**Conclusion:**\nDuring the period of {time_range}, **significant compromise activity with evidence destruction and masquerading** was confirmed on host {hostname}.\n",
        "conclusion_critical": "**Conclusion:**\nDuring the period of {time_range}, **CRITICAL level compromise activity** was confirmed on host {hostname}.\n",
        "conclusion_clean": "**Conclusion:**\nNo significant incident traces were detected within this investigation scope.\n",
        # Attack Methods
        "attack_phishing": "Initial access via phishing (LNK)",
        "attack_masquerade": "Masquerading file placement",
        "attack_timestomp": "Timestamp manipulation (Timestomp)",
        "attack_paradox": "**System time rollback (System Rollback)**",
        "attack_anti": "Evidence wiping (Anti-Forensics)",
        "attack_default": "Suspicious activity",
        "attack_methods_label": "**Primary Attack Methods:**",
        # Deep Dive
        "deep_dive_note": "> **Deep Dive Recommended:** When conducting detailed investigation, start with the **CRITICAL_PHISHING** targets listed in the attached `Pivot_Config.json`. Command line recovery from Event Log (ID 4688) is the highest priority.\n\n",
        # Initial Access
        "dropped_artifacts_header": "**Suspicious Tool/File Introduction (Dropped Artifacts):**\n\n",
        "dropped_table_header": "| File Name | Discovery Time | Origin Trace |\n|---|---|---|\n",
        # Technical Findings
        "anti_forensics_header": "### 🚨 Anti-Forensics Activities (Evidence Destruction)\n\n⚠️⚠️⚠️ **Significant evidence destruction activity detected** ⚠️⚠️⚠️\n\nThe attacker intentionally destroyed evidence of their activities using the following tools:\n\n",
        "missing_evidence_header": "### 📉 Missing Evidence Impact Assessment\n\nThe following evidence is determined to have been lost due to Anti-Forensics tools:\n\n",
        "missing_evidence_table": "| Evidence Category | Expected Information | Status | Estimated Cause |\n|---|---|---|---|\n| LNK Target Paths | `cmd.exe ...` arguments | ❌ Missing | Deleted by BCWipe/SDelete |\n| Prefetch (Tools) | Execution count, timestamps | ❌ Missing | Deleted by CCleaner/BCWipe |\n| Temporary Files | Payload bodies | ❌ Missing | Physical deletion by wiping |\n\n",
        "missing_evidence_note": "🕵️ **Analyst Note:**\nThese evidence gaps are NOT \"tool limitations\" but the result of **\"advanced concealment by the attacker\"**.\nGhost Detection (USN Journal) can only confirm the \"fact that files existed\".\n\n",
        # Technical Findings - Other LNKs
        "high_interest_artifacts": "**High Interest Artifacts:**\n",
        "other_lnks_header": "\n**Other LNKs ({count} files):**\n",
        "other_lnks_desc": "Shortcuts disguised as image filenames. Target_Path information is missing due to wiping, but creation patterns confirm phishing origin.\n",
        "web_download_confirmed": "✅ **Web Download Confirmed** (Gap: {gap})<br/>",
        # Analyst Notes
        "note_timestomp": "Timestamp inconsistency (Timestomp) detected for `{name}`. Evidence of attempts to conceal attack tools.",
        "note_anti_ccleaner": "System cleaner. Used for deleting browser history and MRU.",
        "note_anti_bcwipe": "Military-grade file wiping tool. Makes normal recovery impossible.",
        "note_anti_cleanup": "Presumed to be used for post-attack evidence cleanup.",
        "note_anti_wiped": "Due to execution of this tool, there is an extremely high probability that evidence such as LNK files, Prefetch, and temporary files have been physically overwritten.",
        "note_masquerade_crx": "A Chrome extension (.crx) unrelated to this folder has been placed in the Adobe Reader directory. This is a typical Persistence technique.",
        "note_credentials": "Credential theft or unauthorized tool deployment detected.",
        "note_phishing_lnk": "A suspicious shortcut file was created. Potential phishing attack.",
        "note_web_confirmed": "✅ **Web Download Confirmed** (Gap: {gap})<br/>",
        "note_defcon_masquerade": "⚠️ **Advanced Masquerading Detected**: This filename matches a real DEFCON 22 (2014) presentation. Social engineering suspected to lower target vigilance.<br/>🎭 **Masquerade**: Suspected disguise as security tools or conference materials (DEFCON, etc.).",
        # Plutos Section
        "plutos_header": "## 🌐 5. Critical Network & Exfiltration Traces\nTraces of **data exfiltration**, **unauthorized email data copying**, and **high-risk external communications** detected by the PlutosGate engine.\n\n",
        "plutos_threats_header": "### 🚨 5.1 Critical Threats Detected\n",
        "plutos_map_header": "### 🗺️ 5.2 Critical Activity Map\n",
        "plutos_map_note": "> **Note:** Red indicates external exfiltration or C2 communication, Orange indicates internal lateral movement.\n\n",
        # Recommendations
        "rec_header": "Based on the forensic investigation results for this incident, the following recommended actions are proposed.\n\n### 📋 Recommended Actions\n",
        "rec_table_header": "| Priority | Action | Timeline | Reason |\n|---|---|---|---|\n",
        "rec_p0_evtlog": "| 🔥 **P0** | **Event Log (4688) Command Line Recovery** | **Immediate** | LNK arguments have been wiped, making Event Log the only source for identifying executed commands. |\n",
        "rec_p0_crx": "| 🔥 **P0** | **Analyze Suspicious Chrome Extension (.crx)** | 24 Hours | High probability of functioning as a persistence backdoor; reverse engineering required. |\n",
        "rec_p0_network": "| 🔥 **P0** | **Network Log Analysis (C2 Identification)** | 24 Hours | Identify external communication destination IPs and block at firewall. |\n",
        "rec_p1_lateral": "| 🟡 P1 | **Lateral Movement Check** | 1 Week | Investigate lateral movement to other endpoints on the same network. |\n",
        "rec_p1_creds": "| 🟡 P1 | **Credential Reset** | Immediate | Password reset recommended for all users who used the compromised endpoint. |\n\n",
        # Statistics
        "stats_header": "### 📊 Overall Analysis Summary\n",
        "stats_critical_breakdown": "### 🎯 Critical Detection Breakdown\n",
        "stats_medium_events": "### ⚠️ Medium Confidence Events\n**Total Count:** {count} (See Timeline CSV)\n**Primary Category Distribution:**\n",
        "stats_noise_header": "### 📉 Filtered Noise Statistics\n",
        # IOC Appendix
        "ioc_header": "(Full IOC List)\nComplete list of all Indicators of Compromise (IOC) confirmed in this investigation.\n\n### 📂 File IOCs (Malicious/Suspicious Files)\n",
        # Other LNKs
        "other_lnks_header": "**Other LNKs ({count} files):**\nShortcuts disguised as image filenames. Target_Path information is missing due to wiping, but creation patterns confirm phishing origin.\n",
        # Initial Access - additional keys
        "phishing_confirmed": "**Phishing-based initial access has been confirmed with high confidence.**\n",
        "phishing_lnk_detected": "- **{count}** suspicious LNK files (shortcuts) were detected in Recent folders and similar locations.\n",
        "phishing_table_header": "\n| Sample LNK | Access Time (UTC) | Origin Trace |\n|---|---|---|\n",
        "no_vector_found": "No clear external intrusion vector was automatically detected.\n\n",
        "plutos_no_activity": "No suspicious network activity or lateral movement traces were detected.\n",
    },
    "jp": {
        "title": "インシデント調査報告書",
        "coc_header": "証拠保全および案件情報 (Chain of Custody)",
        "h1_exec": "1. エグゼクティブ・サマリー",
        "h1_origin": "2. 初期侵入経路分析 (Initial Access Vector)",
        "h1_time": "3. 調査タイムライン (Critical Chain)",
        "h1_tech": "4. 技術的詳細 (High Confidence Findings)",
        "h1_stats": "5. 検知統計 (Detection Statistics)",
        "h1_rec": "6. 結論と推奨事項",
        "h1_app": "7. 添付資料 (Critical IOCs Only)",
        "cats": {"INIT": "初期侵入", "C2": "C2通信", "PERSIST": "永続化", "ANTI": "痕跡隠滅", "EXEC": "実行", "DROP": "ファイル作成", "WEB": "Webアクセス"},
        # Executive Summary
        "conclusion_paradox": "**結論:**\n{time_range} の期間において、端末 {hostname} に対する **高度な隠蔽工作を伴う重大な侵害活動** を確認しました。\n\n⚠️🚨 **SYSTEM TIME MANIPULATION DETECTED** 🚨⚠️\n**システム時刻の巻き戻し（Time Paradox）** が検知されました。攻撃者は時刻を操作することでフォレンジック調査を妨害し、ログのタイムラインを意図的に破壊しようとした痕跡があります。タイムライン分析には極めて慎重な精査が必要です。\n",
        "conclusion_anti": "**結論:**\n{time_range} の期間において、端末 {hostname} に対する **証拠隠滅・偽装を伴う重大な侵害活動** を確認しました。\n",
        "conclusion_critical": "**結論:**\n{time_range} の期間において、端末 {hostname} に対する **CRITICAL レベルの侵害活動** を確認しました。\n",
        "conclusion_clean": "**結論:**\n本調査範囲において、重大なインシデントの痕跡は検出されませんでした。\n",
        # Attack Methods
        "attack_phishing": "フィッシング（LNK）による初期侵入",
        "attack_masquerade": "偽装ファイル設置（Masquerading）",
        "attack_timestomp": "タイムスタンプ偽装（Timestomp）",
        "attack_paradox": "**システム時間巻き戻し（System Rollback）**",
        "attack_anti": "痕跡ワイピング（Anti-Forensics）",
        "attack_default": "不審なアクティビティ",
        "attack_methods_label": "**主な攻撃手口:**",
        # Deep Dive
        "deep_dive_note": "> **Deep Dive 推奨:** 詳細な調査を行う際は、添付の `Pivot_Config.json` に記載された **CRITICAL_PHISHING** ターゲット群から開始してください。特にイベントログ（ID 4688）からのコマンドライン復元が最優先事項です。\n\n",
        # Initial Access
        "dropped_artifacts_header": "**不審なツール・ファイルの持ち込み（Dropped Artifacts）:**\n\n",
        "dropped_table_header": "| ファイル名 | 発見場所 | 流入元 (Origin Trace) |\n|---|---|---|\n",
        # Technical Findings
        "anti_forensics_header": "### 🚨 Anti-Forensics Activities (Evidence Destruction)\n\n⚠️⚠️⚠️ **重大な証拠隠滅活動を検出** ⚠️⚠️⚠️\n\n攻撃者は侵入後、以下のツールを使用して活動痕跡を意図的に抹消しています：\n\n",
        "missing_evidence_header": "### 📉 Missing Evidence Impact Assessment\n\n以下の証拠が、Anti-Forensicsツールによって失われたと判断されます：\n\n",
        "missing_evidence_table": "| 証拠カテゴリ | 期待される情報 | 現状 | 推定原因 |\n|---|---|---|---|\n| LNK Target Paths | `cmd.exe ...` 等の引数 | ❌ 欠落 | BCWipe/SDeleteによる削除 |\n| Prefetch (Tools) | 実行回数・タイムスタンプ | ❌ 欠落 | CCleaner/BCWipeによる削除 |\n| 一時ファイル | ペイロード本体 | ❌ 欠落 | ワイピングによる物理削除 |\n\n",
        "missing_evidence_note": "🕵️ **Analyst Note:**\nこれらの証拠欠落は「ツールの限界」ではなく、**「攻撃者による高度な隠蔽工作」**の結果です。\nGhost Detection (USNジャーナル) によりファイルの「存在していた事実」のみを確認できています。\n\n",
        # Analyst Notes
        "note_timestomp": "`{name}` のタイムスタンプに不整合（Timestomp）を確認。攻撃ツールを隠蔽しようとした痕跡です。",
        "note_anti_ccleaner": "システムクリーナー。ブラウザ履歴やMRUの削除に使用されます。",
        "note_anti_bcwipe": "軍事レベルのファイルワイピングツール。通常の復元を不可能にします。",
        "note_anti_cleanup": "攻撃活動終了後の痕跡削除（Cleanup）に使用されたと推定されます。",
        "note_anti_wiped": "このツールの実行により、LNKファイル、Prefetch、一時ファイル等の証拠が物理的に上書き削除された可能性が極めて高いです。",
        "note_masquerade_crx": "Adobe Readerのフォルダに、無関係なChrome拡張機能(.crx)が配置されています。これは典型的なPersistence（永続化）手法です。",
        "note_credentials": "認証情報の窃取または不正ツールの配置を検知しました。",
        "note_phishing_lnk": "不審なショートカットファイルが作成されました。フィッシング攻撃の可能性があります。",
        "note_web_confirmed": "✅ **Web Download Confirmed** (Gap: {gap})<br/>",
        "note_defcon_masquerade": "⚠️ **高度な偽装を検知**: ファイル名は DEFCON 22 (2014) の実際の発表資料と一致します。ターゲットの警戒心を下げるソーシャルエンジニアリングの手口です。<br/>🎭 **Masquerade**: セキュリティツールやカンファレンス資料（DEFCON等）への偽装が疑われます。",
        # Plutos Section
        "plutos_header": "## 🌐 5. 重要ネットワークおよび持ち出し痕跡 (Critical Network & Exfiltration)\nPlutosGateエンジンにより検出された、**データの持ち出し**、**メールデータの不正コピー**、および**高リスクな外部通信**の痕跡。\n\n",
        "plutos_threats_header": "### 🚨 5.1 検出された重大な脅威 (Critical Threats Detected)\n",
        "plutos_map_header": "### 🗺️ 5.2 ネットワーク相関図 (Critical Activity Map)\n",
        "plutos_map_note": "> **Note:** 赤色は外部への持ち出しやC2通信、オレンジ色は内部への横展開を示唆します。\n\n",
        # Recommendations
        "rec_header": "本インシデントにおけるフォレンジック調査結果に基づき、以下の推奨アクションを提案します。\n\n### 📋 Recommended Actions\n",
        "rec_table_header": "| Priority | Action | Timeline | Reason |\n|---|---|---|---|\n",
        "rec_p0_evtlog": "| 🔥 **P0** | **Event Log (4688) Command Line Recovery** | **Immediate** | LNK引数がワイピングされているため、イベントログが唯一の実行コマンド特定源です。 |\n",
        "rec_p0_crx": "| 🔥 **P0** | **Analyze Suspicious Chrome Extension (.crx)** | 24 Hours | 永続化バックドアとして機能している可能性が高いため、リバースエンジニアリングが必要です。 |\n",
        "rec_p0_network": "| 🔥 **P0** | **Network Log Analysis (C2 Identification)** | 24 Hours | 外部通信先IPを特定し、ファイアウォールでブロックしてください。 |\n",
        "rec_p1_lateral": "| 🟡 P1 | **Lateral Movement Check** | 1 Week | 同一ネットワーク内の他端末への横展開を調査してください。 |\n",
        "rec_p1_creds": "| 🟡 P1 | **Credential Reset** | Immediate | 侵害された端末で使用された全ユーザーのパスワードリセットを推奨します。 |\n\n",
        # Statistics
        "stats_header": "### 📊 Overall Analysis Summary\n",
        "stats_critical_breakdown": "### 🎯 Critical Detection Breakdown\n",
        "stats_medium_events": "### ⚠️ Medium Confidence Events\n**Total Count:** {count} 件 (Timeline CSV参照)\n**主なカテゴリ分布:**\n",
        "stats_noise_header": "### 📉 Filtered Noise Statistics\n",
        # IOC Appendix
        "ioc_header": "(Full IOC List)\n本調査で確認されたすべての侵害指標（IOC）の一覧です。\n\n### 📂 File IOCs (Malicious/Suspicious Files)\n",
        # Other LNKs
        "other_lnks_header": "**その他のLNK ({count}件):**\n画像ファイル名を装ったショートカット群です。Target_Path情報はワイピングにより欠落していますが、作成パターンからフィッシング由来と断定されます。\n",
        # Initial Access - additional keys
        "phishing_confirmed": "**フィッシングによる初期侵入が高確度で確認されました。**\n",
        "phishing_lnk_detected": "- Recentフォルダ等において、**{count}件** の不審なLNKファイル（ショートカット）へのアクセスが検知されています。\n",
        "phishing_table_header": "\n| サンプルLNK | アクセス時刻 (UTC) | 流入元 (Origin Trace) |\n|---|---|---|\n",
        "no_vector_found": "明確な外部侵入ベクターは自動検知されませんでした。\n\n",
        "plutos_no_activity": "不審なネットワーク活動や横展開の痕跡は検出されませんでした。\n",
    }
}

class LachesisIntel:
    def __init__(self, base_dir="."):
        self.loader = ThemisLoader(["rules/triage_rules.yaml"])
        self.dual_use_keywords = self.loader.get_dual_use_keywords()
        self.noise_stats = {}
        
        # [Refactor] Load Full Yaml
        self.full_config = self._load_intel_signatures()
        self.intel_sigs = self.full_config.get("signatures", [])
        self.lachesis_conf = self.full_config.get("lachesis_config", {})
        
        # [v2.0] Load and validate scoring_rules.yaml with Pydantic
        self._load_validated_scoring_rules()
        
        # Load Config Values
        self.garbage_paths = self.lachesis_conf.get("garbage_paths", [])
        self.trusted_roots = self.lachesis_conf.get("trusted_system_roots", [])
        self.suspicious_subdirs = self.lachesis_conf.get("suspicious_subdirs", ["/temp", "/tmp", "/users/public", "/appdata", "/programdata", "downloads", "documents", "desktop"])
        self.infra_ips = set(self.lachesis_conf.get("infra_ips", []))
        self.force_include_tags = self.lachesis_conf.get("force_include_tags", [])
        self.force_include_types = self.lachesis_conf.get("force_include_types", [])

    def _load_validated_scoring_rules(self):
        """[v2.0] Load scoring_rules.yaml with Pydantic validation"""
        try:
            from tools.rule_validator import validate_scoring_rules
            scoring_path = Path(__file__).parent.parent.parent / "rules" / "scoring_rules.yaml"
            validated_rules = validate_scoring_rules(str(scoring_path))
            
            # Merge into full_config for access via self.get()
            self.full_config["threat_scores"] = validated_rules.get("threat_scores", [])
            self.full_config["garbage_patterns"] = validated_rules.get("garbage_patterns", [])
            self.full_config["unc_lateral_tools"] = validated_rules.get("unc_lateral_tools", [])
            self.full_config["context_boosts"] = validated_rules.get("context_boosts", {})
        except ImportError:
            print("    [!] rule_validator not available. Loading without Pydantic validation.")
            self._load_scoring_rules_fallback()
        except SystemExit as e:
            # Re-raise fatal validation errors
            raise e
        except Exception as e:
            print(f"    [!] Scoring rules validation warning: {e}")
            self._load_scoring_rules_fallback()
    
    def _load_scoring_rules_fallback(self):
        """Fallback loader without Pydantic validation"""
        scoring_path = Path(__file__).parent.parent.parent / "rules" / "scoring_rules.yaml"
        if scoring_path.exists():
            try:
                with open(scoring_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                self.full_config["threat_scores"] = data.get("threat_scores", [])
                self.full_config["garbage_patterns"] = data.get("garbage_patterns", [])
                self.full_config["unc_lateral_tools"] = data.get("unc_lateral_tools", [])
            except Exception as e:
                print(f"    [!] Failed to load scoring_rules.yaml: {e}")

    def get(self, key, default=None):
        """Access top-level config keys (e.g., correlation_rules)"""
        return self.full_config.get(key, default)

    def _load_intel_signatures(self):
        """Load Intelligence Signatures from YAML"""
        sig_path = Path(__file__).parent.parent.parent / "rules" / "intel_signatures.yaml"
        if sig_path.exists():
            try:
                with open(sig_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data: return data
            except Exception as e:
                print(f"    [!] Failed to load intel signatures: {e}")
        return {}

    def match_intel(self, text):
        """Check text against loaded intelligence signatures."""
        if not text or not self.intel_sigs: return None
        text_lower = str(text).lower()
        
        for sig in self.intel_sigs:
            for kw in sig.get("keywords", []):
                if kw.lower() in text_lower:
                    return sig.get("description", "")
        return None

    def is_trusted_system_path(self, path):
        p = str(path).lower().replace("\\", "/")
        if not self.trusted_roots:
             # Fallback if config failed
             return False
        if any(s in p for s in self.suspicious_subdirs): return False
        return any(root in p for root in self.trusted_roots)

    def is_noise(self, name, path=""):
        name = str(name).strip().lower()
        path = str(path).strip().lower().replace("\\", "/")
        
        for gp in self.garbage_paths:
            if gp in path:
                self.log_noise("Garbage Path", gp)
                return True
        if re.match(r'^[a-f0-9]{32,64}$', name): return True
        if name.endswith(".db") or name.endswith(".dat") or name.endswith(".log"): return True
        return False

    def log_noise(self, reason, value):
        if reason not in self.noise_stats: self.noise_stats[reason] = 0
        self.noise_stats[reason] += 1

    def is_dual_use(self, name):
        name_lower = str(name).lower()
        return any(k in name_lower for k in self.dual_use_keywords)
    
    def is_visual_noise(self, name):
        name = str(name).strip()
        if len(name) < 3: return True
        return False


# ═══════════════════════════════════════════════════════════
# [v6.6] IntelManager - Centralized Intelligence Data
# ═══════════════════════════════════════════════════════════
class IntelManager:
    """
    Centralized intelligence data management.
    Separates data from logic for better maintainability.
    """
    
    @staticmethod
    def get_renderer_noise_patterns():
        """
        [v6.7] Returns ultra-hard noise patterns for report cleanup.
        Now synchronizes with filter_rules.yaml through ThemisLoader.
        """
        # 1. Load patterns from YAML via ThemisLoader
        loader = ThemisLoader(["rules/filter_rules.yaml"])
        yaml_patterns = loader.get_noise_regex_list()
        
        # 2. Add ultra-specific renderer patterns (some are complex regex better kept here)
        renderer_specific = [
            # WinSxS and System Components (Renderer-side specifics)
            r"_none_",  # WinSxS hash pattern: xxx_10.0.17134.1_none_xxx
            r"_10.0.",  # Windows version pattern in component names
            r"microsoft\.windows\.contentdeliverymanager",
            r"microsoft\.windows\.cortana",
            r"microsoft\.windows\.",
            r"microsoft\.ui\.",
            r"microsoft\.net\.",
            # System Update Components
            r"\\prov\\runtime",
            r"microsoft-windows-appmodel-runtime",
            r"microsoft-windows-client",
            r"usocoreworker\.exe",
            r"backgroundtransferapi",
            r"devicesearchcache",
            r"appcache",
            r"fight_flight",
            # XAMPP Metadata (Dynamic service artifacts)
            r"\.frm$",
            r"\.myd$",
            r"\.myi$",
            r"performance_schema\\",
            # Information schema (MySQL system tables)
            r"information_schema\\",
            r"mysql\\mysql\\",
            # Tomcat/Java artifacts
            r"catalina\\",
            # Language Resources
            r".mui",
            r"en-us\\",
            r"ja-jp\\",
        ]
        
        # 3. Combine and deduplicate
        combined = list(set(yaml_patterns + renderer_specific))
        return combined

    @staticmethod
    def get_safe_users():
        """Returns list of system/default users to ignore."""
        return [
            "IEUSER", "PUBLIC", "DEFAULT", "ALL USERS", "DESKTOP", 
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", 
            "ADMINISTRATOR", "GUEST", "DEFAULTACCOUNT"
        ]
    
    @staticmethod
    def get_rescue_tags():
        """Returns tags that protect events from noise filtering."""
        return [
            "CRITICAL", "EVIL", "WEBSHELL", "RANSOM", "WIPE", 
            "LATERAL", "MIMIKATZ", "EXFIL", "DEFACEMENT", "MALICIOUS", "STAGING_TOOL"
        ]

    @staticmethod
    def get_garbage_patterns():
        """
        [v2.0] Load garbage patterns from scoring_rules.yaml
        Falls back to hardcoded patterns if YAML not available.
        """
        try:
            from pathlib import Path
            yaml_path = Path(__file__).parent.parent.parent / "rules" / "scoring_rules.yaml"
            if yaml_path.exists():
                import yaml
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "garbage_patterns" in data:
                        return data["garbage_patterns"]
        except Exception:
            pass
        
        # Fallback patterns
        return [
            r"windows\\winsxs", 
            r"windows\\assembly", 
            r"windows\\microsoft\.net", 
            r"windows\\servicing",
            r"windows\\systemapps",
            r"windows\\inf",
            r"windows\\driverstore",
            r"driverstore", 
            r"windows\\diagtrack",
            r"windows\\biometry",
            r"windows\\softwaredistribution",
            r"program files\\windowsapps",
            r"windowsapps", 
            r"deletedalluserpackages",
            r"\\apprepository",
            r"\\contentdeliverymanager",
            r"\\infusedapps",
            r"system32\\driverstore",
            r"windows\\system32\\wbem",
            r"windows\\system32\\catroot",
            r"windows\\system32\\config\\systemprofile",
            r"windows\\web\\",
            r"windows\\branding\\",
            r"programdata\\microsoft\\windows\\systemdata",
            r"appdata\\local\\microsoft\\windows\\inetcache",
            r"appdata\\local\\google\\chrome\\user data\\default\\cache",
            r"temporary internet files",
            r"content\.ie5",
            r"telemetry",
            r"tracking",
            r"advertising",
            r"google-analytics",
            r"doubleclick",
            r"scorecardresearch",
            r"windows\\system32\\fntcache",
            r"windows\\system32\\ime",
            r"windows\\system32\\logfiles",
            r"windows\\system32\\winbioplugins",
            r"appdata\\local\\microsoft\\clr_v4\.0\\usage",
            r"atatus\.mp4", # Rule 3 for tutorial videos
            r"tutorial",
            r"advertisement",
            r"beacon",
            r"pixel",
            r"quantserve",
            r"adnxs",
            r"rubiconproject",
            r"openx",
            r"pubmatic",
            r"criteo",
            r"casalemedia",
            r"tapad",
        ]