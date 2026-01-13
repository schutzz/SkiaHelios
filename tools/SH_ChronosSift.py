import polars as pl
import argparse
import sys
import os
import re
from typing import Optional, List

# 既存モジュール
from tools.SH_ThemisLoader import ThemisLoader
from tools.SH_HestiaCensorship import Hestia
# 新規統合: イカロス・パラドックス
from tools.SH_IcarusParadox import IcarusParadox, IcarusConfig, IcarusDirection

# ============================================================
#  SH_ChronosSift v3.5 [Plan B: Precision Correlation Model]
#  Mission: Timeline Anomaly Detection & Artifact Cross-Check
#  Update: Microburst Detection + Execution Evidence Cross-Check
#  
#  Plan B Logic:
#    A. Microburst Detection (秒単位50件以上 → Update Storm)
#    B. Execution Evidence Cross-Check (System32のみ、実行証拠なし → 白)
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v3.5 - Plan B
        " "      "Time bows to the Law."
    """)

class ChronosEngine:
    def __init__(self, tolerance=60.0, config=None):
        self.tolerance = tolerance
        self.hestia = Hestia()
        self.config = config or {}
        
        # Load whitelist and context scoring from config
        self.timestomp_whitelist = self._build_whitelist_patterns()
        self.context_scoring = self.config.get("context_scoring", {})
        self.is_forensic_host = False  # Will be set during analyze()
        
        # Icarus設定 (Chronosの許容誤差と同期)
        icarus_config = IcarusConfig(
            tolerance_sec=tolerance,
            melting_point_sec=60.0, # 60秒以上の乖離で「溶解(矛盾)」と判定
            prefetch_direction=IcarusDirection.BIDIRECTIONAL,
            usn_direction=IcarusDirection.BIDIRECTIONAL
        )
        self.icarus = IcarusParadox(icarus_config)
        
        # 正規の時刻同期プロセス定義
        self.ALLOWED_TIME_AGENTS = {
            "vboxservice.exe": [r"program files.*oracle.*virtualbox", r"system32"],
            "vmtoolsd.exe": [r"program files.*vmware", r"system32"],
            "w32tm.exe": [r"system32"],
            "svchost.exe": [r"system32"] 
        }

    def _build_whitelist_patterns(self):
        """Build compiled regex patterns from timestomp_whitelist config"""
        patterns = []
        whitelist = self.config.get("timestomp_whitelist", {})
        for category, pattern_list in whitelist.items():
            if isinstance(pattern_list, list):
                for pat in pattern_list:
                    try:
                        patterns.append(re.compile(pat))
                    except re.error:
                        pass
        return patterns
    
    def _check_forensic_host(self, hostname, username):
        """Check if this is a forensic workstation based on hostname/username"""
        indicators = self.context_scoring.get("forensic_indicators", {})
        
        for pat in indicators.get("hostnames", []):
            if hostname and re.search(pat, hostname):
                return True
        for pat in indicators.get("usernames", []):
            if username and re.search(pat, username):
                return True
        return False
    
    def _get_sysinternals_score(self, filename):
        """Get appropriate score for SysInternals tools based on context"""
        patterns = self.context_scoring.get("sysinternals_patterns", [])
        scores = self.context_scoring.get("sysinternals_scores", {})
        
        # Check if filename matches SysInternals patterns
        for pat in patterns:
            if re.search(pat, filename):
                if self.is_forensic_host:
                    return scores.get("forensic_host", {}).get("timestomp", 30)
                else:
                    return scores.get("default", {}).get("timestomp", 100)
        return None  # Not a SysInternals tool
    
    def _is_whitelisted(self, filename):
        """Check if filename matches any whitelist pattern"""
        for pattern in self.timestomp_whitelist:
            if pattern.search(filename):
                return True
        return False

    # ===========================================
    # Plan B Logic A: Microburst Detection (Update Storm Filter)
    # ===========================================
    def _detect_microburst(self, df, time_col="SI_CreationTime_Raw"):
        """
        秒単位で50件以上の同一タイムスタンプ → Update Storm として白判定。
        攻撃者が50件以上を ミリ秒単位で完全一致させることは現実的に不可能。
        """
        if time_col not in df.columns:
            # [FIX] Fallback to Timestamp_UTC if SI_CreationTime is missing
            if "Timestamp_UTC" in df.columns:
                print("       [i] Falling back to Timestamp_UTC for Microburst detection")
                time_col = "Timestamp_UTC"
            else:
                return df
        
        print("    -> [Plan B:A] Detecting Update Storm (Microburst)...")
        
        # 秒単位に丸める（ミリ秒を削除）
        # [FIX] Ensure type is string before slicing
        df = df.with_columns(
            pl.col(time_col).cast(pl.Utf8).str.slice(0, 19).alias("_time_sec")
        )
        
        # 各秒のファイル数をカウント
        time_counts = df.group_by("_time_sec").agg(pl.len().alias("_count"))
        
        # 50件以上の秒をバルク更新と判定
        bulk_times = time_counts.filter(pl.col("_count") >= 50)["_time_sec"].to_list()
        
        if bulk_times:
            print(f"       >> [BULK UPDATE] Detected {len(bulk_times)} Update Storm intervals ({sum(df.filter(pl.col('_time_sec').is_in(bulk_times)).height for _ in [1])} files)")
            
            is_bulk = pl.col("_time_sec").is_in(bulk_times)
            
            df = df.with_columns([
                pl.when(is_bulk & (pl.col("Threat_Tag").str.contains("TIMESTOMP")))
                  .then(pl.lit("INFO_BULK_UPDATE"))
                  .otherwise(pl.col("Threat_Tag"))
                  .alias("Threat_Tag"),
                
                pl.when(is_bulk & (pl.col("Chronos_Score") > 0))
                  .then(0)
                  .otherwise(pl.col("Chronos_Score"))
                  .alias("Chronos_Score")
            ])
        
        return df.drop(["_time_sec"])
    
    # ===========================================
    # Plan B Logic B: Execution Evidence Cross-Check
    # ===========================================
    def _check_execution_evidence(self, df, prefetch_files=None, amcache_files=None):
        """
        System32/SysWOW64/WinSxS 内のファイルに対して実行証拠をチェック。
        実行証拠なし → Score 0 (Update残骸)
        実行証拠あり → Score 維持 (悪用の可能性)
        
        ※ ユーザーディレクトリ（Downloads, Temp, Desktop）は対象外（常に黒維持）
        """
        print("    -> [Plan B:B] Checking Execution Evidence (Alibi Check)...")
        
        # システムパスパターン
        system_path_pattern = r"(?i)(\\windows\\system32\\|\\windows\\syswow64\\|\\windows\\winsxs\\)"
        
        # ユーザーパスパターン（これらは実行証拠に関わらず黒維持）
        user_path_pattern = r"(?i)(\\users\\[^\\]+\\(downloads|desktop|documents|temp|appdata\\local\\temp)\\)"
        
        if "ParentPath" not in df.columns:
            return df
        
        # 実行済みファイルリストを構築
        executed_files = set()
        
        # Prefetch から実行ファイル名を抽出
        if prefetch_files:
            for pf in prefetch_files:
                try:
                    pf_df = pl.read_csv(pf, ignore_errors=True, infer_schema_length=0)
                    if "ExecutableName" in pf_df.columns:
                        executed_files.update(pf_df["ExecutableName"].str.to_lowercase().unique().to_list())
                    elif "SourceFilename" in pf_df.columns:
                        executed_files.update(pf_df["SourceFilename"].str.to_lowercase().unique().to_list())
                except: pass
        
        # Amcache から実行ファイル名を抽出
        if amcache_files:
            for ac in amcache_files:
                try:
                    ac_df = pl.read_csv(ac, ignore_errors=True, infer_schema_length=0)
                    if "FullPath" in ac_df.columns:
                        # ファイル名のみを抽出
                        names = ac_df["FullPath"].str.split("\\").list.get(-1).str.to_lowercase().unique().to_list()
                        executed_files.update([n for n in names if n])
                except: pass
        
        if not executed_files:
            print("       [i] No execution evidence loaded, skipping alibi check")
            return df
        
        print(f"       >> Loaded {len(executed_files)} executed file names for cross-check")
        
        # システムパス内かどうか
        is_system_path = pl.col("ParentPath").str.contains(system_path_pattern)
        
        # ユーザーパス内かどうか（実行証拠チェック対象外）
        is_user_path = pl.col("ParentPath").str.contains(user_path_pattern)
        
        # ファイル名が実行済みリストに含まれるか
        df = df.with_columns(
            pl.col("FileName").fill_null("").str.to_lowercase().alias("_fn_lower")
        )
        has_execution = pl.col("_fn_lower").is_in(list(executed_files))
        
        # Logic B 適用:
        # システムパス内 + 実行証拠なし + TIMESTOMPタグ → Score = 0
        df = df.with_columns([
            pl.when(
                is_system_path & 
                (~is_user_path) & 
                (~has_execution) & 
                (pl.col("Threat_Tag").str.contains("TIMESTOMP"))
            )
              .then(pl.lit("INFO_SYSTEM_UPDATE"))
              .otherwise(pl.col("Threat_Tag"))
              .alias("Threat_Tag"),
            
            pl.when(
                is_system_path & 
                (~is_user_path) & 
                (~has_execution) & 
                (pl.col("Chronos_Score") > 0)
            )
              .then(0)
              .otherwise(pl.col("Chronos_Score"))
              .alias("Chronos_Score")
        ])
        
        return df.drop(["_fn_lower"])

    def _ensure_columns(self, lf):
        """カラムの存在を保証する（Threat_Tagの初期化を含む）"""
        cols = lf.collect_schema().names()
        
        if "ParentPath" not in cols and "Target_Path" in cols:
            print("    -> [Chronos] Splitting Target_Path into ParentPath/FileName...")
            lf = lf.with_columns(
                pl.col("Target_Path").str.replace_all(r"/", "\\") 
            )
            lf = lf.with_columns([
                pl.col("Target_Path").str.split("\\").list.get(-1).alias("FileName"),
                pl.col("Target_Path").str.split("\\").list.slice(0, -1).list.join("\\").alias("ParentPath")
            ])
        
        expected = ["ParentPath", "FileName", "Action", "Tag", "Threat_Score", "Threat_Tag", "Anomaly_Time"]
        
        cols = lf.collect_schema().names()
        for c in expected:
            if c not in cols: 
                if c == "Threat_Score":
                    lf = lf.with_columns(pl.lit(0).alias(c))
                else:
                    lf = lf.with_columns(pl.lit("").alias(c))
            
        return lf

    def check_null_timestamps(self, lf):
        """
        [Logic v4: Context-Based Scoring + Whitelist]
        1. Whitelisted files (installers, VM tools) -> Score 0
        2. SysInternals tools -> Context-based (30 for forensic hosts, 100 for general)
        3. Other executables with Null Time -> Score 300 (CRITICAL)
        4. LNK Files:
           - Double Extension (.jpg.lnk) -> CRITICAL (Phishing/Masquerade)
           - Single Extension (Chrome.lnk) -> Score 0 (Innocent)
        """
        # Collect to apply per-row logic, then convert back
        df = lf.collect()
        
        results = []
        for row in df.iter_rows(named=True):
            filename = row.get("FileName", "") or ""
            si_creation = row.get("SI_CreationTime")
            parent_path = row.get("ParentPath", "") or ""
            
            # Check if null timestamp
            is_null = si_creation is None or (hasattr(si_creation, 'year') and si_creation.year < 1980)

            # [FIX] Ignore Non-Filesystem Artifacts (UserAssist, EventLog, etc.) from Null Stomp Check
            # Even if they have "exe" extension, they don't have MFT Creation Time.
            artifact_type = row.get("Artifact_Type", "")
            if artifact_type and artifact_type not in ["MFT", "LogFile", "UsnJournal"]:
                is_null = False # Skip this check for non-FS artifacts
            
            if not is_null:
                results.append({"score": row.get("Threat_Score", 0), "tag": row.get("Threat_Tag", ""), "anomaly": row.get("Anomaly_Time", "")})
                continue
            
            filename_lower = filename.lower()
            
            # Check noise paths
            noise_keywords = ["cache", "temporary internet files", "history", "cookies"]
            if any(kw in parent_path.lower() for kw in noise_keywords):
                results.append({"score": 0, "tag": "NOISE_CACHE", "anomaly": ""})
                continue
            
            # Check if whitelisted (installers, VM tools)
            if self._is_whitelisted(filename):
                results.append({"score": 0, "tag": "INFO_WHITELISTED", "anomaly": ""})
                continue
            
            # Check if SysInternals tool -> context-based scoring
            sysinternals_score = self._get_sysinternals_score(filename)
            if sysinternals_score is not None:
                tag = "SYSINTERNALS_TIMESTOMP" if not self.is_forensic_host else "INFO_FORENSIC_TOOL"
                results.append({"score": sysinternals_score, "tag": tag, "anomaly": "-"})
                continue
            
            # Check target extensions
            target_exts = [".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js"]
            is_target_ext = any(filename_lower.endswith(ext) for ext in target_exts)
            
            # LNK handling
            is_lnk = filename_lower.endswith(".lnk")
            has_double_ext = bool(re.search(r"\.(jpg|png|pdf|docx|xlsx|txt|zip|rar)\.lnk$", filename_lower))
            
            if is_target_ext:
                results.append({"score": 300, "tag": "CRITICAL_NULL_TIMESTOMP", "anomaly": "-"})
            elif is_lnk and has_double_ext:
                results.append({"score": 250, "tag": "CRITICAL_PHISHING_LNK", "anomaly": "-"})
            elif is_lnk:
                results.append({"score": 0, "tag": "INFO_NULL_TIMESTAMP", "anomaly": ""})
            else:
                results.append({"score": 0, "tag": "INFO_NULL_TIMESTAMP", "anomaly": ""})
        
        # Apply results back to DataFrame
        scores = [r["score"] for r in results]
        tags = [r["tag"] for r in results]
        anomalies = [r["anomaly"] for r in results]
        
        df = df.with_columns([
            pl.Series("Threat_Score", scores),
            pl.Series("Threat_Tag", tags),
            pl.Series("Anomaly_Time", anomalies)
        ])
        
        return df.lazy()

    def _detect_usn_rollback(self, lf):
        """USNジャーナルの「時間の逆行」を検知する"""
        cols = lf.collect_schema().names()
        if "UpdateSequenceNumber" not in cols or "UpdateTimestamp" not in cols:
            return lf

        print("    -> [Chronos] USN Journal detected. Scanning for Time Paradoxes (System Rollback)...")
        
        lf = lf.with_columns(
            pl.col("UpdateSequenceNumber").cast(pl.Int64, strict=False).alias("UpdateSequenceNumber_Int")
        )
        lf = lf.with_columns(
            pl.col("UpdateTimestamp").str.replace("T", " ").str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("_dt")
        )

        lf = lf.sort("UpdateSequenceNumber_Int")
        lf = lf.with_columns([
            pl.col("_dt").shift(1).alias("_prev_dt"),
        ])

        rollback_threshold = -1.0 * 60 

        lf = lf.with_columns(
            (pl.col("_dt") - pl.col("_prev_dt")).dt.total_seconds().alias("_time_diff")
        )

        # Define extreme future condition
        extreme_future_threshold = 365 * 24 * 60 * 60 * 10
        extreme_cond = (pl.col("_time_diff") > extreme_future_threshold)

        lf = lf.with_columns(
            pl.when(extreme_cond)
            .then(pl.lit("TIMESTOMP_FUTURE_EXTREME"))
            .otherwise(pl.lit(""))
            .alias("Anomaly_Extreme")
        )
        
        lf = lf.with_columns(
             pl.when(pl.col("Anomaly_Extreme") == "TIMESTOMP_FUTURE_EXTREME")
             .then(300)
             .otherwise(pl.col("Threat_Score"))
             .alias("Threat_Score"),

             pl.when(pl.col("Anomaly_Extreme") == "TIMESTOMP_FUTURE_EXTREME")
             .then(pl.lit("CRITICAL_TIMESTOMP"))
             .otherwise(pl.col("Threat_Tag"))
             .alias("Threat_Tag"),
             
             pl.when(pl.col("Anomaly_Extreme") == "TIMESTOMP_FUTURE_EXTREME")
             .then(pl.lit("TIMESTOMP_FUTURE_EXTREME"))
             .otherwise(pl.col("Anomaly_Time"))
             .alias("Anomaly_Time")
        )
        
        lf = lf.with_columns(
            pl.when(pl.col("_time_diff") < rollback_threshold)
              .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK")) 
              .otherwise(pl.col("Anomaly_Time"))
              .alias("Anomaly_Time")
        )

        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(300) 
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score")
        )
        
        lf = lf.with_columns(
            pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
              .then(pl.format("{} (Rollback: {} sec)", pl.col("FileName"), pl.col("_time_diff")))
              .otherwise(pl.col("FileName"))
              .alias("FileName")
        )

        return lf.drop(["_dt", "_prev_dt", "_time_diff", "UpdateSequenceNumber_Int"])

    def _detect_mft_timestomp(self, lf):
        # 7. MFT Timestomp 検知 (Extreme Future etc.)
        cols = lf.collect_schema().names()
        si_cr, fn_cr = "SI_CreationTime", "FileName_Created"
        
        if "SI_CreationTime_Raw" in cols and "si_dt" in cols:
            extreme_cond = (
                (pl.col("SI_CreationTime_Raw").is_not_null()) & 
                (pl.col("si_dt").is_null()) &
                (pl.col("SI_CreationTime_Raw").str.len_chars() > 10)
            ) | (pl.col("si_dt").dt.year() > 2030)

            lf = lf.with_columns([
                pl.when(extreme_cond)
                  .then(pl.lit("TIMESTOMP_FUTURE_EXTREME"))
                  .otherwise(pl.lit(""))
                  .alias("Anomaly_Extreme")
            ])

            # Smart Filter: Keep valid dates OR extreme anomalies
            lf = lf.filter(
                (pl.col("si_dt").is_not_null() & pl.col("fn_dt").is_not_null()) | 
                (pl.col("Anomaly_Extreme") != "")
            )

            lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().fill_null(0).alias("diff_sec"))

            lf = lf.with_columns([
                pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
                  .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK"))
                .when(pl.col("Threat_Tag").str.contains("CRITICAL_TIMESTOMP"))
                  .then(pl.lit("CRITICAL_TIMESTOMP_ATTEMPT"))
                .when((pl.col("Threat_Score") >= 80) & (pl.col("Threat_Tag") != "NOISE_ARTIFACT"))
                  .then(pl.lit("CRITICAL_ARTIFACT"))
                .when(pl.col("diff_sec") < -60)
                  .then(pl.lit("INFO_UPDATE_PATTERN")) # [FIX] Regular Update
                .when(pl.col("diff_sec") > self.tolerance)
                  .then(pl.lit("TIMESTOMP_BACKDATE")) # [FIX] Backdating (MFT is older than Created)
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                
                pl.when(pl.col("si_dt").dt.microsecond() == 0)
                  .then(pl.lit("ZERO_PRECISION"))
                  .otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            score_expr = (
                pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").then(300)
                .when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                .when(pl.col("Threat_Tag") == "INFO_VM_TIME_SYNC").then(0)
                .when(pl.col("Threat_Tag") == "INFO_NULL_TIMESTAMP").then(0)
                .when(pl.col("Anomaly_Time") == "INFO_UPDATE_PATTERN").then(0) # [FIX] Score 0 for updates
                .when(pl.col("Threat_Tag").str.contains("CRITICAL")).then(300) 
                .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(200) # [FIX] Score 200 for backdate
                .otherwise(0)
            )
            lf = lf.with_columns(score_expr.alias("Chronos_Score"))
        else:
            print("    [!] MFT Timestamps not found. Skipping Standard Timestomp detection.")
            lf = lf.with_columns([
                pl.lit("").alias("Anomaly_Time"),
                pl.lit("").alias("Anomaly_Zero"),
                pl.lit(0).alias("Chronos_Score")
            ])
        
        return lf.drop(["_dt", "_prev_dt", "_time_diff", "UpdateSequenceNumber_Int"])

    def _detect_system_time_context(self, lf):
        """
        Themisスコアリングの「後」に実行。
        正規のVBoxServiceなどを救済し、未知のツールを断罪する。
        """
        print("    -> [Chronos] Contextualizing System Time Changes (VM Sync vs Attack)...")
        
        is_time_event = (
            pl.col("Action").str.to_lowercase().str.contains("system time|change") |
            pl.col("Tag").str.contains("4616|TIME")
        )

        # ホワイトリスト判定
        is_legit = pl.lit(False)
        for agent, paths in self.ALLOWED_TIME_AGENTS.items():
            name_match = pl.col("FileName").str.to_lowercase().str.contains(agent)
            path_match = pl.lit(False)
            for p in paths:
                path_match = path_match | pl.col("ParentPath").str.to_lowercase().str.contains(p)
            
            is_legit = is_legit | (name_match & path_match)

        # スコア書き換え
        lf = lf.with_columns([
            pl.when(is_time_event)
              .then(
                  pl.when(is_legit)
                    .then(0) # 正規なら0点
                    .otherwise(300) # 偽装or不明なら300点
              )
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score"),
            
            pl.when(is_time_event)
              .then(
                  pl.when(is_legit)
                    .then(pl.lit("INFO_VM_TIME_SYNC"))
                    .otherwise(pl.lit("CRITICAL_TIMESTOMP_ATTEMPT"))
              )
              .otherwise(pl.col("Threat_Tag"))
              .alias("Threat_Tag")
        ])

        return lf

    def _apply_safety_filters(self, df):
        print("    -> [Chronos] Applying Safety Filters (Brutal Mode)...")
        
        df = df.with_columns([
            pl.col("ParentPath").fill_null("").str.to_lowercase().alias("_pp"),
            pl.col("FileName").fill_null("").str.to_lowercase().alias("_fn")
        ])
        
        # [CRITICAL FIX] アンチフォレンジックツールは削除リストから除外！
        # "ccleaner", "jetico", "bcwipe" を削除しました。
        kill_keywords = [
            "dropbox", 
            "skype", "onedrive", "google", "adobe", 
            "mozilla", "firefox", 
            "notepad++", "intel", "mcafee", "true key",
            "microsoft analysis services", "as oledb",
            "windows defender", "windows media player",
            "windows journal", "winsat", "toastdata",
            "package repository", "installshield",
            "assembly", "servicing", "winsxs", "microsoft.net",
            "windows/installer", "windows\\installer",
            "programdata/microsoft/windows", "programdata\\microsoft\\windows",
            "appdata/local/temp", "appdata\\local\\temp",
            "appdata/local/microsoft/windows", "appdata\\local\\microsoft\\windows",
            "windows/system32/config", "windows\\system32\\config"
        ]
        
        file_kill_list = ["desktop.ini", "thumbs.db", "ntuser.dat", "usrclass.dat", "iconcache.db"]
        dual_use_folders = ["nmap", "wireshark", "python", "perl", "ruby", "tor browser"]
        protected_binaries = ["nmap.exe", "zenmap.exe", "ncat.exe", "python.exe", "pythonw.exe", "tor.exe"]

        is_noise = pl.lit(False)
        for kw in kill_keywords:
            is_noise = is_noise | pl.col("_pp").str.contains(kw, literal=True)
        for kw in file_kill_list:
            is_noise = is_noise | pl.col("_fn").str.contains(kw, literal=True)

        is_tool_folder = pl.lit(False)
        for tool in dual_use_folders:
            is_tool_folder = is_tool_folder | pl.col("_pp").str.contains(tool, literal=True)
            
        is_protected = pl.col("_fn").is_in(protected_binaries)
        is_noise = is_noise | (is_tool_folder & (~is_protected))

        # CRITICALタグがついているものはノイズ判定を強制キャンセル
        is_critical_context = pl.col("Threat_Tag").str.contains("CRITICAL")

        df = df.with_columns([
            pl.when(is_noise & (~is_critical_context)) 
              .then(pl.lit("NOISE_ARTIFACT"))
              .otherwise(pl.col("Threat_Tag"))
              .alias("Threat_Tag"),
            
            pl.when(is_noise & (~is_critical_context))
              .then(0)
              .otherwise(pl.col("Threat_Score"))
              .alias("Threat_Score")
        ])

        return df.drop(["_pp", "_fn"])

    def _detect_mft_timestomp(self, lf):
        # 7. MFT Timestomp 検知 (Extreme Future etc.)
        cols = lf.collect_schema().names()
        si_cr, fn_cr = "SI_CreationTime", "FileName_Created"
        
        if "SI_CreationTime_Raw" in cols and "si_dt" in cols:
            extreme_cond = (
                (pl.col("SI_CreationTime_Raw").is_not_null()) & 
                (pl.col("si_dt").is_null()) &
                (pl.col("SI_CreationTime_Raw").str.len_chars() > 10)
            ) | (pl.col("si_dt").dt.year() > 2030)

            lf = lf.with_columns([
                pl.when(extreme_cond)
                  .then(pl.lit("TIMESTOMP_FUTURE_EXTREME"))
                  .otherwise(pl.lit(""))
                  .alias("Anomaly_Extreme")
            ])

            # Smart Filter: Keep valid dates OR extreme anomalies
            lf = lf.filter(
                (pl.col("si_dt").is_not_null() & pl.col("fn_dt").is_not_null()) | 
                (pl.col("Anomaly_Extreme") != "")
            )

            lf = lf.with_columns((pl.col("fn_dt") - pl.col("si_dt")).dt.total_seconds().fill_null(0).alias("diff_sec"))

            lf = lf.with_columns([
                pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK")
                  .then(pl.lit("CRITICAL_SYSTEM_ROLLBACK"))
                .when(pl.col("Threat_Tag").str.contains("CRITICAL_TIMESTOMP"))
                  .then(pl.lit("CRITICAL_TIMESTOMP_ATTEMPT"))
                .when((pl.col("Threat_Score") >= 80) & (pl.col("Threat_Tag") != "NOISE_ARTIFACT"))
                  .then(pl.lit("CRITICAL_ARTIFACT"))
                .when(pl.col("diff_sec") < -60)
                  .then(pl.lit("INFO_UPDATE_PATTERN")) # [FIX] Regular Update
                .when(pl.col("diff_sec") > self.tolerance)
                  .then(pl.lit("TIMESTOMP_BACKDATE")) # [FIX] Backdating (MFT is older than Created)
                .otherwise(pl.lit("")).alias("Anomaly_Time"),
                
                pl.when(pl.col("si_dt").dt.microsecond() == 0)
                  .then(pl.lit("ZERO_PRECISION"))
                  .otherwise(pl.lit("")).alias("Anomaly_Zero")
            ])
            
            score_expr = (
                pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").then(300)
                .when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                .when(pl.col("Threat_Tag") == "INFO_VM_TIME_SYNC").then(0)
                .when(pl.col("Threat_Tag") == "INFO_NULL_TIMESTAMP").then(0)
                .when(pl.col("Anomaly_Time") == "INFO_UPDATE_PATTERN").then(0) # [FIX] Score 0 for updates
                .when(pl.col("Threat_Tag").str.contains("CRITICAL")).then(300) 
                .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(200) # [FIX] Score 200 for backdate
                .otherwise(0)
            )
            lf = lf.with_columns(score_expr.alias("Chronos_Score"))
        else:
            print("    [!] MFT Timestamps not found. Skipping Standard Timestomp detection.")
            lf = lf.with_columns([
                pl.lit("").alias("Anomaly_Time"),
                pl.lit("").alias("Anomaly_Zero"),
                pl.lit(0).alias("Chronos_Score")
            ])
        
        return lf

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v3.4 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader(["rules/triage_rules.yaml", "rules/sigma_file_event.yaml", "rules/intel_signatures.yaml"])
            lf = pl.read_csv(args.file, ignore_errors=True, infer_schema_length=0).lazy()
            
            # Normalize Columns
            cols = lf.collect_schema().names()
            mapping = {}
            if "Created0x10" in cols: mapping["Created0x10"] = "SI_CreationTime"
            if "Created0x30" in cols: mapping["Created0x30"] = "FileName_Created"
            if "LastModified0x10" in cols: mapping["LastModified0x10"] = "StandardInformation_Modified"
            if "LastModified0x30" in cols: mapping["LastModified0x30"] = "FileName_Modified"
            
            if mapping:
                lf = lf.rename(mapping)

            # Early Safe Date Parsing
            time_cols = ["SI_CreationTime", "FileName_Created", "StandardInformation_Modified", "FileName_Modified"]
            cols = lf.collect_schema().names()
            
            exprs = []
            for c in time_cols:
                if c in cols:
                    exprs.append(pl.col(c).str.replace("T", " "))
            
            if exprs:
                lf = lf.with_columns(exprs)
                lf = lf.with_columns([
                    pl.col("SI_CreationTime").alias("SI_CreationTime_Raw"),
                    pl.col("FileName_Created").alias("FileName_Created_Raw")
                ])

                parse_exprs = []
                for c in time_cols:
                    if c in cols:
                        parse_exprs.append(pl.col(c).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False))
                        if c == "SI_CreationTime": parse_exprs.append(pl.col(c).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("si_dt"))
                        if c == "FileName_Created": parse_exprs.append(pl.col(c).str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False).alias("fn_dt"))
                
                lf = lf.with_columns(parse_exprs)

            # 1. カラム保証
            lf = self._ensure_columns(lf)

            # 2. USN ロールバック検知
            lf = self._detect_usn_rollback(lf)
            
            # Safety Net for Missing Time Columns
            current_cols = lf.collect_schema().names()
            for t_col in time_cols:
                if t_col not in current_cols:
                    lf = lf.with_columns(pl.lit(None, dtype=pl.Datetime).alias(t_col))

            # 3. [CRITICAL] Context-Aware Null Timestamp Check
            lf = self.check_null_timestamps(lf)
            
            # 4. Themis脅威スコアリング
            print("    -> Applying Themis Threat Scoring...")
            lf = loader.apply_threat_scoring(lf)
            
            if "Threat_Score" in lf.collect_schema().names():
                lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

            # 5. コンテキスト判定 (VM同期など)
            lf = self._detect_system_time_context(lf)

            # 6. 安全フィルタ (ノイズ削除)
            lf = self._apply_safety_filters(lf)
            
            # 7. MFT Timestomp 検知 (Extreme Future etc.)
            lf = self._detect_mft_timestomp(lf)

            # --- Icarus Integration ---
            icarus_results = []
            if args.prefetch or args.shimcache or args.usnj:
                print("\n[*] Invoking Icarus Paradox Engine...")
                if args.prefetch:
                    try:
                        pf_lf = pl.scan_csv(args.prefetch, ignore_errors=True, infer_schema_length=0)
                        res = self.icarus.inspect_prefetch(lf, pf_lf)
                        icarus_results.append(res)
                    except Exception as e:
                        print(f"    [!] Prefetch Analysis Failed: {e}")

                if args.shimcache:
                    try:
                        sc_lf = pl.scan_csv(args.shimcache, ignore_errors=True, infer_schema_length=0)
                        res = self.icarus.inspect_shimcache(lf, sc_lf)
                        icarus_results.append(res)
                    except Exception as e:
                        print(f"    [!] ShimCache Analysis Failed: {e}")

            # Results Consolidation
            df = lf.filter(pl.col("Chronos_Score") > 0).collect()
            
            # Logic A: Microburst Detection (Update Storm Filter)
            # Use 'SI_CreationTime' as it is guaranteed to exist in the output DF (string format)
            # [Fix] Ensure SI_CreationTime is String before passing to _detect_microburst
            if "SI_CreationTime" in df.columns and df.schema["SI_CreationTime"] != pl.Utf8:
                 df = df.with_columns(pl.col("SI_CreationTime").cast(pl.Utf8))
            
            df = self._detect_microburst(df, time_col="SI_CreationTime")
            
            # Logic B: Execution Evidence Cross-Check
            # Load Prefetch/Amcache files for alibi check
            prefetch_files = []
            amcache_files = []
            if args.prefetch:
                prefetch_files = [args.prefetch]
            
            # Auto-detect Amcache in args if available (or from KAPE directory structure)
            kape_base = getattr(args, 'kape_dir', None)
            if kape_base:
                from pathlib import Path
                # Chronos might verify kape_base string/path
                amcache_files = list(Path(kape_base).rglob("*Amcache*.csv"))
            
            df = self._check_execution_evidence(df, prefetch_files=prefetch_files, amcache_files=amcache_files)
            
            # Filter again after Plan B (remove newly zeroed items)
            # Also ensure we filter out INFO tags if they have 0 score
            df = df.filter(pl.col("Chronos_Score") > 0)

            if icarus_results:
                print("    -> Merging Icarus Anomalies into Timeline...")
                if "Key_Full" not in df.columns:
                    df = df.with_columns(
                        (pl.col("ParentPath").fill_null("").str.to_lowercase().str.replace_all("/", "\\").str.strip_chars("\\") + "\\" + 
                         pl.col("FileName").fill_null("").str.to_lowercase()).alias("Key_Full")
                    )

                for res_lazy in icarus_results:
                    res_df = res_lazy.collect()
                    if res_df.height > 0:
                        print(f"       [!] Icarus detected {res_df.height} paradoxes!")
                        df = df.join(
                            res_df.select(["Key_Full", "Anomaly_Type", "Icarus_Score"]),
                            on="Key_Full",
                            how="left"
                        )
                        df = df.with_columns([
                            (pl.col("Chronos_Score").fill_null(0) + pl.col("Icarus_Score").fill_null(0)).alias("New_Score"),
                            pl.concat_str([
                                pl.col("Threat_Tag"), 
                                pl.lit(" "), 
                                pl.col("Anomaly_Type").fill_null("")
                            ]).str.strip_chars().alias("New_Tag")
                        ])
                        df = df.drop(["Chronos_Score", "Threat_Tag", "Icarus_Score", "Anomaly_Type"])
                        df = df.rename({"New_Score": "Chronos_Score", "New_Tag": "Threat_Tag"})

            # USNJ Targeted Scan
            if args.usnj:
                suspects = []
                if df.height > 0:
                     suspects = df.filter(pl.col("Chronos_Score") > 50)["Key_Full"].to_list()
                
                if suspects:
                    try:
                        usn_lf = pl.scan_csv(args.usnj, ignore_errors=True, infer_schema_length=0)
                        mft_reuse = df.lazy()
                        usn_res = self.icarus.inspect_usnj_safe(mft_reuse, usn_lf, suspects).collect()
                        
                        if usn_res.height > 0:
                            print(f"       [!] Icarus (USN) confirmed {usn_res.height} paradoxes!")
                            df = df.join(
                                usn_res.select(["Key_Full", "Anomaly_Type", "Icarus_Score"]),
                                on="Key_Full", how="left"
                            )
                            df = df.with_columns([
                                (pl.col("Chronos_Score") + pl.col("Icarus_Score").fill_null(0)).alias("Chronos_Score"),
                                pl.concat_str([pl.col("Threat_Tag"), pl.lit(" "), pl.col("Anomaly_Type").fill_null("")]).alias("Threat_Tag")
                            ]).drop(["Icarus_Score", "Anomaly_Type"])
                    except Exception as e:
                        print(f"    [!] USN Analysis Failed: {e}")

            # Output Finalization
            if "ParentPath" in df.columns:
                df = self.hestia.apply_censorship(df, "ParentPath", "FileName")
            
            print(f"    [DEBUG] Final DF Height: {df.height}")
            if df.height > 0:
                df = df.sort("Chronos_Score", descending=True)
                try:
                    df.write_csv(args.out)
                    print(f"[+] Analysis Complete. Anomalies: {df.height} -> Saved to {args.out}")
                except Exception as e:
                    print(f"    [!] WRITE FAILED: {e}")
                # print(f"    [Rollback] Anomaly writing disabled (clean report mode). Height: {df.height}")
            else:
                print("\n[*] Clean: No significant anomalies found.")
                try:
                    pl.DataFrame({
                        "Chronos_Score": [], "Anomaly_Time": [], "FileName": [], "ParentPath": [], "Threat_Tag": []
                    }).write_csv(args.out)
                    print(f"    [DEBUG] Wrote empty file to {args.out}")
                except Exception as e:
                    print(f"    [!] EMPTY WRITE FAILED: {e}")

        except Exception as e:
            print(f"[!] Chronos Critical Failure: {e}")
            import traceback
            traceback.print_exc()

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Main MFT CSV file")
    parser.add_argument("--prefetch", help="Prefetch CSV for Icarus Paradox check")
    parser.add_argument("--shimcache", help="ShimCache CSV for Icarus Paradox check")
    parser.add_argument("--usnj", help="USN Journal CSV for Icarus Paradox check")
    parser.add_argument("-o", "--out", default="Chronos_Results.csv")
    parser.add_argument("-t", "--tolerance", type=float, default=60.0)
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--start", help="Ignored")
    parser.add_argument("--end", help="Ignored")
    parser.add_argument("--hostname", help="Target hostname for context detection")
    parser.add_argument("--username", help="Primary username for context detection")
    args = parser.parse_args(argv)
    
    # Load config from YAML
    import yaml
    config = {}
    config_path = os.path.join(os.path.dirname(__file__), "..", "rules", "intel_signatures.yaml")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            print(f"    -> Loaded config from intel_signatures.yaml")
        except Exception as e:
            print(f"    -> Config load failed: {e}")
    
    engine = ChronosEngine(args.tolerance, config=config)
    
    # Set forensic host detection based on hostname/username
    if args.hostname or args.username:
        engine.is_forensic_host = engine._check_forensic_host(args.hostname, args.username)
        if engine.is_forensic_host:
            print(f"    -> [CONTEXT] Detected forensic workstation: SysInternals scores reduced")
    
    engine.analyze(args)

if __name__ == "__main__":
    main()