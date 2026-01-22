"""
InsightGenerator - IOC Insight Generation Module
Extracted from sh_analyzer.py for better modularity.

This module handles:
- Generating human-readable insights for IOCs
- Multi-language support (Japanese/English)
- Pattern-based insight templates
"""
import re


class InsightGenerator:
    """
    [v3.0] IOC Insight Generation Engine.
    Migrated from LachesisAnalyzer.generate_ioc_insight for modularity.
    """
    
    def __init__(self, intel_module, txt_resources):
        """
        Args:
            intel_module: Intel module for threat intelligence matching
            txt_resources: Text resources dictionary for internationalization
        """
        self.intel = intel_module
        self.txt = txt_resources
    
    def generate(self, ioc) -> str:
        """
        Generate human-readable insight for an IOC.
        
        Args:
            ioc: IOC dictionary with Type, Tag, Value, Path, etc.
            
        Returns:
            str: HTML-formatted insight string, or None
        """
        ioc_type = str(ioc.get('Type', '')).upper()
        tag = str(ioc.get('Tag', '')).upper()
        val = str(ioc.get('Value', ''))
        val_lower = val.lower()
        reason = str(ioc.get('Reason', '')).upper()
        path = str(ioc.get('Path', ''))
        payload = str(ioc.get('Payload', ''))
        
        # Phantom Drive Detection
        is_phantom_drive = val.startswith("A:\\") or val.startswith("A:/") or "A:\\\\" in val
        is_phantom_drive = is_phantom_drive or any(kw in val_lower for kw in ["phantom drive", "fake update", "attack tooling", "remote access setup"])
        
        if is_phantom_drive:
            return self._insight_phantom_drive(val, val_lower, tag)
        
        # ConsoleHost_history.txt
        if "consolehost_history" in val_lower:
            return self._insight_console_history(val, payload)
        
        # Defender Tampering
        if "DEFENDER_DISABLE" in tag or "defender tampering" in val_lower:
            return self._insight_defender_tampering(val, payload)
        
        # Hosts File Modification
        if "HOSTS_FILE_MODIFICATION" in tag:
            return self._insight_hosts_modification(val, payload)
        
        # Anti-Forensics
        if "ANTI_FORENSICS" in ioc_type:
            return "🚨 **Evidence Destruction**: 証拠隠滅ツールです。実行回数やタイムスタンプを確認してください。"
        
        # SAM Scavenge
        if "SAM_SCAVENGE" in tag or "SAM_SCAVENGE" in ioc_type:
            return self._insight_sam_scavenge(val, val_lower, path)
        
        # WebShell
        if "WEBSHELL" in tag or "WEBSHELL" in ioc_type:
            return self._insight_webshell(val, val_lower, path)
        
        # User Creation / Privilege Escalation
        if "USER_CREATION" in tag or "PRIVILEGE_ESCALATION" in tag or "SAM_REGISTRY" in tag:
            return self._insight_user_creation(val, val_lower, tag)
        
        # Log Deletion
        if "LOG_DELETION" in tag or "EVIDENCE_WIPING" in tag:
            return self._insight_log_deletion(val, val_lower)
        
        # Execution Confirmed
        if "EXECUTION_CONFIRMED" in ioc_type:
            return "🚨 **Confirmed**: このツールは実際に実行された痕跡があります。調査優先度：高"
        
        # Time Paradox
        if "TIME_PARADOX" in ioc_type or "ROLLBACK" in reason:
            return self._insight_time_paradox(val)
        
        # Masquerade
        if "MASQUERADE" in ioc_type:
            return self._insight_masquerade(val, val_lower, path, ioc)
        
        # LNK with suspicious tags
        if ".lnk" in val_lower and any(t in ioc_type for t in ["SUSPICIOUS", "PHISHING", "PS_", "CMD_", "MSHTA"]):
            return self._insight_suspicious_lnk(ioc, val, val_lower, ioc_type, path)
        
        if "PHISHING" in ioc_type:
            return "フィッシング活動に関連するアーティファクトを検知しました。"
        
        if "TIMESTOMP" in ioc_type:
            name = ioc.get("Value", "Unknown")
            return self.txt.get("note_timestomp", "タイムスタンプ異常を検知: {name}").format(name=name)
        
        if "CREDENTIALS" in ioc_type:
            return "認証情報の窃取または不正ツールの配置を検知しました。"
        
        if "COMMUNICATION_CONFIRMED" in reason or "COMMUNICATION_CONFIRMED" in ioc_type:
            return "🚨 ブラウザ履歴との照合により、**実際にネットワーク通信が成功した痕跡**を確認しました。C2サーバへのビーコン送信、またはペイロードダウンロードの可能性が極めて高いです。"
        
        return None
    
    def _insight_phantom_drive(self, val, val_lower, tag):
        insights = ["💾 **Phantom Drive Execution Detected** (外部メディアからの実行)"]
        insights.append(f"- **Artifact**: `{val}`")
        
        if any(kw in val_lower for kw in ["update", "patch", "upgrade"]):
            insights.append("- 🚨 **Fake Update Suspicion**: 更新プログラムを装った偽装スクリプトの可能性があります。")
        elif any(kw in val_lower for kw in ["setup", "install", "provision", "deploy"]):
            insights.append("- 🔧 **Attack Tooling**: セットアップ・展開用スクリプトと推定されます。")
        elif any(kw in val_lower for kw in ["winrm", "remote", "ssh", "psexec", "wmi"]):
            insights.append("- 🌐 **Remote Access**: リモートアクセスを有効化するスクリプトです。")
        elif any(kw in val_lower for kw in ["persist", "autologon", "startup", "schedule"]):
            insights.append("- 🔁 **Persistence**: 永続化メカニズムに関連するスクリプトです。")
        
        insights.append("- ⚠️ **Impact**: 外部メディア（USB等）からの実行により、Cドライブのフォレンジック痕跡を回避しています。")
        insights.append("- 🔍 **Next Step**: USBデバイスの接続履歴（setupapi.dev.log, USBSTOR）を調査してください。")
        return "<br/>".join(insights)
    
    def _insight_console_history(self, val, payload):
        insights = ["📜 **PowerShell Command History Detected** (ConsoleHost_history.txt)"]
        insights.append("- **File**: PowerShell の履歴ファイルを検知しました。")
        
        if payload and payload != val and "[complex" not in payload.lower():
            insights.append("")
            insights.append("📝 **Raw Evidence**:")
            insights.append("```")
            insights.append(f"{payload[:500]}" if len(payload) > 500 else payload)
            insights.append("```")
        else:
            insights.append("- ⚠️ 元データにコマンド内容が含まれていません。ファイルを直接確認してください。")
        
        insights.append("")
        insights.append("- 🔍 **Next Step**: このファイルの内容を直接確認し、実行されたコマンドを特定してください。")
        return "<br/>".join(insights)
    
    def _insight_defender_tampering(self, val, payload):
        insights = ["🛡️ **Defender Tampering Detected** (リアルタイム保護の無効化)"]
        insights.append("- **Detection**: DEFENDER_DISABLE タグに基づく検知です。")
        insights.append("- ⚠️ **Severity**: CRITICAL")
        
        if payload and payload != val and "[complex" not in payload.lower():
            insights.append("")
            insights.append("📝 **Raw Evidence**:")
            insights.append("```")
            insights.append(f"{payload[:500]}" if len(payload) > 500 else payload)
            insights.append("```")
        else:
            insights.append("- ⚠️ 元データにコマンド内容が含まれていません。イベントログを直接確認してください。")
        
        insights.append("")
        insights.append("- 🔍 **Next Step**: イベントログ (Microsoft-Windows-Windows Defender/Operational) を確認してください。")
        return "<br/>".join(insights)
    
    def _insight_hosts_modification(self, val, payload):
        insights = ["📝 **Hosts File Modification Detected**"]
        insights.append("- **Target**: `%SystemRoot%\\System32\\drivers\\etc\\hosts`")
        insights.append("- ⚠️ **Impact**: DNS解決を改ざんし、C2通信やフィッシングに利用された可能性があります。")
        insights.append("- 🔍 **Next Step**: hostsファイルの内容を確認し、不審なドメイン/IPマッピングを特定してください。")
        
        if payload and payload != val and "[complex" not in payload.lower():
            insights.append("")
            insights.append("📝 **Raw Evidence**:")
            insights.append("```")
            insights.append(f"{payload[:300]}" if len(payload) > 300 else payload)
            insights.append("```")
        
        return "<br/>".join(insights)
    
    def _insight_sam_scavenge(self, val, val_lower, path):
        insights = ["☠️ **Chain Scavenger Detection** (Dirty Hive Hunter)"]
        insights.append("- **Detection**: 破損または隠蔽されたSAMハイブから、バイナリレベルのカービングでユーザーアカウントを物理抽出しました。")
        
        if "[HEX:" in path:
            try:
                hex_part = path.split("[HEX:")[1].split("]")[0].strip()
                insights.append(f"- **Binary Context**: `{hex_part}`")
            except: pass

        if "hacker" in val_lower or "user" in val_lower:
            insights.append(f"- **Suspicion**: ユーザー名 `{val}` は典型的な攻撃用アカウントの命名パターンです。")
        insights.append("- **Action**: 即時にこのアカウントの作成日時周辺（イベントログ削除の痕跡がある場合はその直前）のタイムラインを確認してください。[LOG_WIPE_INDUCED_MISSING_EVENT]")
        return "\n".join(insights)
    
    def _insight_webshell(self, val, val_lower, path):
        insights = ["🕷️ **CRITICAL WebShell Detection**"]
        
        if "tmp" in val_lower and ".php" in val_lower:
            insights.append("- **Pattern**: `tmp*.php` - SQLインジェクション攻撃によって動的生成されたWebShellの典型的なファイル名です。")
            insights.append("- **Attack Vector**: 高確率で IIS/Apache への SQL Injection 経由のRCE (Remote Code Execution) です。")
        elif any(x in val_lower for x in ["c99", "r57", "b374k", "wso", "chopper"]):
            insights.append("- **Signature**: 既知のWebShellシグネチャ（China Chopper, c99, r57など）を検知しました。")
        else:
            insights.append("- **Detection**: Webサーバーディレクトリ内のスクリプトファイルを検知しました。")
        
        if "htdocs" in path.lower() or "wwwroot" in path.lower() or "inetpub" in path.lower():
            insights.append("- **Location**: Webルートディレクトリ内に配置 → 外部からのHTTPアクセス可能な状態です。")
        insights.append("- **Next Step**: IISログの同時刻リクエスト、w3wp.exe のプロセス履歴を即座に調査してください。")
        return "<br/>".join(insights)
    
    def _insight_user_creation(self, val, val_lower, tag):
        insights = ["👤 **CRITICAL: User Creation/Privilege Escalation Detected**"]
        
        if "4720" in val or "user" in val_lower:
            insights.append("- **Event**: 新規ユーザーアカウントが作成されました (EID 4720)。")
        if "4732" in val or "4728" in val:
            insights.append("- **Event**: ユーザーがセキュリティグループに追加されました。")
        if "administrators" in val_lower:
            insights.append("- **Impact**: **Administrator権限の付与** - 最高権限の取得です。")
        if "remote" in val_lower and "desktop" in val_lower:
            insights.append("- **Impact**: **Remote Desktop Usersへの追加** - RDP経由の永続アクセスが可能になりました。")
        if "sam" in val_lower or "SAM" in tag:
            insights.append("- **Registry**: SAMレジストリへのアクセス - ローカルアカウント情報の操作が行われています。")
        
        insights.append("- **Next Step**: net user /domain で作成されたアカウントを確認、即座に無効化してください。")
        return "<br/>".join(insights)
    
    def _insight_log_deletion(self, val, val_lower):
        insights = ["🗑️ **CRITICAL: Log Deletion/Evidence Wiping Detected**"]
        
        if "1102" in val:
            insights.append("- **Event**: Securityログがクリアされました (EID 1102)。")
        if "104" in val:
            insights.append("- **Event**: Systemログがクリアされました (EID 104)。")
        if "wevtutil" in val_lower or "clear-eventlog" in val_lower:
            insights.append("- **Tool**: イベントログ消去コマンドが実行されました。")
        if "clearev" in val_lower:
            insights.append("- **Tool**: Meterpreter clearevコマンド - 攻撃者がログを完全消去しようとしています。")
        if "usnjrnl" in val_lower or "mft" in val_lower:
            insights.append("- **Target**: ファイルシステムジャーナル ($USNJRNL/$MFT) の削除 - フォレンジック証拠の抹消です。")
        
        insights.append("- **Impact**: **アンチフォレンジック活動** - 攻撃者が活動痕跡を隠蔽しようとしています。")
        insights.append("- **Next Step**: バックアップログ、VSS (Volume Shadow Copy) からの復元を試みてください。")
        return "<br/>".join(insights)
    
    def _insight_time_paradox(self, val):
        rb_sec = "Unknown"
        if "Rollback:" in val:
            match = re.search(r"Rollback:\s*(-?\d+)", val)
            if match: rb_sec = match.group(1)
        return f"USNジャーナルの整合性分析により、システム時刻の巻き戻し(約{rb_sec}秒)を検知しました。これは高度なアンチフォレンジック活動を示唆します。"
    
    def _insight_masquerade(self, val, val_lower, path, ioc):
        is_sysinternals = "sysinternals" in val_lower or "procexp" in val_lower or "autoruns" in val_lower or "psexec" in val_lower or "procmon" in val_lower
        is_user_path = any(p in path.lower() for p in ["downloads", "public", "temp", "appdata"])
        
        if is_sysinternals or is_user_path:
            insights = ["🔧 **攻撃ツールセットの展開を検知**"]
            if is_sysinternals:
                insights.append(f"- **Tool**: `{val}` は Sysinternalsツール群（または類似ツール）と推定されます。")
            if is_user_path:
                insights.append(f"- **Location**: ユーザーパス (`{path}`) から実行 - 典型的な攻撃者の手法です。")
            insights.append("- **Intent**: 🎯 **Possible Hands-on-Keyboard Intrusion** (Short Burst Activity)")
            insights.append("- **Note**: 管理者のメンテナンス作業ではなく、攻撃者による手動探索の可能性が高いです。")
            return "<br/>".join(insights)
        
        elif ".crx" in val_lower:
            masq_app = "正規アプリケーション"
            if "adobe" in path.lower(): masq_app = "Adobe Reader"
            elif "microsoft" in path.lower(): masq_app = "Microsoft Office"
            elif "google" in path.lower(): masq_app = "Google Chrome"
            return f"{masq_app}のフォルダに、無関係なChrome拡張機能(.crx)が配置されています。これは典型的なPersistence（永続化）手法です。"
        else:
            return f"正規ファイル名を偽装した不審なファイル (`{val}`) を検知しました。マルウェアの可能性があります。"
    
    def _insight_suspicious_lnk(self, ioc, val, val_lower, ioc_type, path):
        insights = []
        extra = ioc.get('Extra', {})
        target = extra.get('Target_Path', '')
        args = extra.get('Arguments', '')
        risk = extra.get('Risk', '')

        intel_desc = self.intel.match_intel(val) if hasattr(self.intel, 'match_intel') else None
        if intel_desc:
            insights.append(intel_desc)

        if not target:
            if "Target:" in val: target = val.split("Target:")[-1].strip()
            elif "🎯" in val: target = val.split("🎯")[-1].strip()
        
        if target:
            insights.append(f"🎯 **Target**: `{target}`")
            
            if "cmd.exe" in target.lower() or "powershell" in target.lower():
                insights.append("⚠️ **Critical**: OS標準シェルを悪用した攻撃の起点です。")
            elif ".exe" in target.lower() or ".bat" in target.lower() or ".vbs" in target.lower():
                insights.append("⚠️ **High**: 実行可能ファイルを呼び出すショートカットです。")

        if args:
            args_disp = (args[:100] + "...") if len(args) > 100 else args
            insights.append(f"📝 **Args**: `{args_disp}`")
            
            if "-enc" in args.lower() or "-encoded" in args.lower():
                insights.append("🚫 **Encoded**: Base64エンコードされたPowerShellコマンドを検知。即座に解析が必要です。")
            if "-windowstyle hidden" in args.lower() or "-w hidden" in args.lower():
                insights.append("🕶️ **Stealth**: ユーザーからウィンドウを隠蔽するフラグを確認。")
        else:
            if "-enc" in target.lower():
                insights.append("🚫 **Encoded**: ターゲットパス内にエンコードされたコマンドを確認。")

        if risk == "SECURITY_TOOL_MASQUERADE":
            insights.append("🎭 **Masquerade**: セキュリティツールやカンファレンス資料(DEFCON等)への偽装が疑われます。")

        if insights:
            return "<br/>".join(insights)
        elif "PHISHING" in ioc_type:
            return "不審なショートカットファイルが作成されました。フィッシング攻撃の可能性があります。"
        else:
            return "不審なショートカットファイルを検知しました。"
