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
#  SH_ChronosSift v3.6 [Plan B: Compatibility Patch]
#  Mission: Timeline Anomaly Detection & Artifact Cross-Check
#  Update: Fixed Icarus USN Type Mismatch (Datetime vs String)
# ============================================================

def print_logo():
    print(r"""
       (   )
      (  :  )   < CHRONOS SIFT >
       (   )     v3.6 - Plan B
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
    def _detect_microburst(self, df, time_col="SI_CreationTime"):
        """
        [Optimized] 秒単位で50件以上の同一タイムスタンプ → Update Storm として判定。
        文字列変換(cast)を避け、Datetime型(si_dt)が利用可能な場合は高速truncateを使用する。
        """
        if df.height == 0:
            return df

        print("    -> [Plan B:A] Detecting Update Storm (Microburst)...")
        
        # [OPTIMIZATION] Use pre-parsed datetime column if available
        if "si_dt" in df.columns:
            # Datetime Truncate is much faster/lighter than String Slice
            df = df.with_columns(
                pl.col("si_dt").dt.truncate("1s").cast(pl.Utf8).fill_null("").alias("_time_sec")
            )
        else:
            # Fallback to String Slicing (Slow)
            if time_col not in df.columns:
                if "Timestamp_UTC" in df.columns:
                    time_col = "Timestamp_UTC"
                else:
                    return df
            
            df = df.with_columns(
                pl.col(time_col).cast(pl.Utf8, strict=False).str.slice(0, 19).fill_null("").alias("_time_sec")
            )
        
        # Filter out empty times
        df_valid = df.filter(pl.col("_time_sec") != "")
        if df_valid.height == 0:
             return df.drop(["_time_sec"]) if "_time_sec" in df.columns else df

        # 各秒のファイル数をカウント
        time_counts = df_valid.group_by("_time_sec").agg(pl.len().alias("_count"))
        
        # 50件以上の秒をバルク更新と判定
        bulk_times = time_counts.filter(pl.col("_count") >= 50)["_time_sec"].to_list()
        
        if bulk_times:
            # 高速化: print用の再計算を削除し、一度のフィルタリングで適用
            is_bulk = pl.col("_time_sec").is_in(bulk_times)
            affected_count = df.filter(is_bulk).height
            print(f"       >> [BULK UPDATE] Detected {len(bulk_times)} intervals affecting {affected_count} artifacts.")
            
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
        [OPTIMIZED] Vectorized null timestamp check using Polars expressions.
        Replaces slow iter_rows loop with columnar operations.
        """
        # Ensure required columns exist
        cols = lf.collect_schema().names()
        
        # Define column references with fallbacks
        filename_col = pl.col("FileName").fill_null("")
        filename_lower = filename_col.str.to_lowercase()
        parent_path_col = pl.col("ParentPath").fill_null("") if "ParentPath" in cols else pl.lit("")
        parent_path_lower = parent_path_col.str.to_lowercase()
        
        # SI_CreationTime null check (vectorized)
        # Handle both None and pre-1980 dates
        # [FIX] Proper operator precedence with explicit construction
        si_col = "SI_CreationTime" if "SI_CreationTime" in cols else "si_dt"
        if si_col in cols:
            if "si_dt" in cols:
                # si_dt is datetime - can check year
                is_null_ts = pl.col(si_col).is_null() | (pl.col("si_dt").dt.year() < 1980)
            else:
                is_null_ts = pl.col(si_col).is_null()
        else:
            is_null_ts = pl.lit(False)

        
        # Non-filesystem artifact check (skip null check for UserAssist, EventLog, etc.)
        if "Artifact_Type" in cols:
            is_fs_artifact = pl.col("Artifact_Type").fill_null("").is_in(["MFT", "LogFile", "UsnJournal", ""])
        else:
            is_fs_artifact = pl.lit(True)
        
        # Combined null condition: only flag if null AND is filesystem artifact
        is_null = is_null_ts & is_fs_artifact
        
        # Noise path patterns (vectorized)
        noise_pattern = r"(?i)(cache|temporary internet files|history|cookies)"
        is_noise_path = parent_path_lower.str.contains(noise_pattern)
        
        # Whitelist patterns (from config)
        whitelist_patterns = self.config.get("timestomp_whitelist", {})
        all_patterns = []
        for category, pattern_list in whitelist_patterns.items():
            if isinstance(pattern_list, list):
                all_patterns.extend(pattern_list)
        
        if all_patterns:
            whitelist_regex = "(?i)(" + "|".join(all_patterns) + ")"
            is_whitelisted = filename_col.str.contains(whitelist_regex)
        else:
            is_whitelisted = pl.lit(False)
        
        # SysInternals patterns (from config)
        sysinternals_patterns = self.config.get("context_scoring", {}).get("sysinternals_patterns", [])
        if sysinternals_patterns:
            sysinternals_regex = "(?i)(" + "|".join(sysinternals_patterns) + ")"
            is_sysinternals = filename_col.str.contains(sysinternals_regex)
        else:
            is_sysinternals = pl.lit(False)
        
        # Target extension check (vectorized)
        target_ext_pattern = r"(?i)\.(exe|dll|sys|ps1|bat|cmd|vbs|js)$"
        is_target_ext = filename_lower.str.contains(target_ext_pattern)
        
        # LNK file checks
        is_lnk = filename_lower.str.ends_with(".lnk")
        double_ext_pattern = r"(?i)\.(jpg|png|pdf|docx|xlsx|txt|zip|rar)\.lnk$"
        has_double_ext = filename_lower.str.contains(double_ext_pattern)
        
        # SysInternals scoring based on context
        sysinternals_scores = self.config.get("context_scoring", {}).get("sysinternals_scores", {})
        forensic_score = sysinternals_scores.get("forensic_host", {}).get("timestomp", 30)
        default_score = sysinternals_scores.get("default", {}).get("timestomp", 100)
        sysinternals_score_val = forensic_score if self.is_forensic_host else default_score
        sysinternals_tag = "INFO_FORENSIC_TOOL" if self.is_forensic_host else "SYSINTERNALS_TIMESTOMP"
        
        # Build score expression (cascading conditions)
        score_expr = (
            pl.when(~is_null)
              .then(pl.col("Threat_Score").fill_null(0))
            .when(is_noise_path)
              .then(pl.lit(0))
            .when(is_whitelisted)
              .then(pl.lit(0))
            .when(is_sysinternals)
              .then(pl.lit(sysinternals_score_val))
            .when(is_target_ext)
              .then(pl.lit(300))
            .when(is_lnk & has_double_ext)
              .then(pl.lit(250))
            .otherwise(pl.lit(0))
        )
        
        # Build tag expression (cascading conditions)
        tag_expr = (
            pl.when(~is_null)
              .then(pl.col("Threat_Tag").fill_null(""))
            .when(is_noise_path)
              .then(pl.lit("NOISE_CACHE"))
            .when(is_whitelisted)
              .then(pl.lit("INFO_WHITELISTED"))
            .when(is_sysinternals)
              .then(pl.lit(sysinternals_tag))
            .when(is_target_ext)
              .then(pl.lit("CRITICAL_NULL_TIMESTOMP"))
            .when(is_lnk & has_double_ext)
              .then(pl.lit("CRITICAL_PHISHING_LNK"))
            .when(is_lnk)
              .then(pl.lit("INFO_NULL_TIMESTAMP"))
            .otherwise(pl.lit("INFO_NULL_TIMESTAMP"))
        )
        
        # Build anomaly expression
        anomaly_expr = (
            pl.when(~is_null)
              .then(pl.col("Anomaly_Time").fill_null(""))
            .when(is_sysinternals | is_target_ext | (is_lnk & has_double_ext))
              .then(pl.lit("-"))
            .otherwise(pl.lit(""))
        )
        
        # Apply all expressions in one pass
        lf = lf.with_columns([
            score_expr.alias("Threat_Score"),
            tag_expr.alias("Threat_Tag"),
            anomaly_expr.alias("Anomaly_Time")
        ])
        
        return lf


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

            # Smart Filter: Keep valid dates OR extreme anomalies OR HIGH-VALUE ARTIFACTS
            # [FIX v8.2] Do NOT delete rows that already have high Threat_Score or critical tags
            is_high_value = (
                (pl.col("Threat_Score") >= 500) | 
                pl.col("Threat_Tag").str.contains("METASPLOIT|COBALT|MIMIKATZ|EXPLOIT|C2|CRITICAL")
            )
            lf = lf.filter(
                (pl.col("si_dt").is_not_null() & pl.col("fn_dt").is_not_null()) | 
                (pl.col("Anomaly_Extreme") != "") |
                is_high_value  # [FIX v8.2] High-value artifacts bypass timestamp filter
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
            
            # [FIX v9.0] Chronos_Score should PRESERVE existing Threat_Score from Sigma rules
            # The old logic used .otherwise(0) which destroyed Sigma scores for files without timestamp anomalies
            score_expr = (
                pl.when(pl.col("Anomaly_Time") == "CRITICAL_SYSTEM_ROLLBACK").then(300)
                .when(pl.col("Threat_Tag") == "NOISE_ARTIFACT").then(0)
                .when(pl.col("Threat_Tag") == "INFO_VM_TIME_SYNC").then(0)
                .when(pl.col("Threat_Tag") == "INFO_NULL_TIMESTAMP").then(0)
                .when(pl.col("Anomaly_Time") == "INFO_UPDATE_PATTERN").then(0)
                .when(pl.col("Threat_Tag").str.contains("CRITICAL")).then(300) 
                .when(pl.col("Anomaly_Time") == "CRITICAL_ARTIFACT").then(200)
                .when(pl.col("Anomaly_Time") == "TIMESTOMP_BACKDATE").then(200)
                .otherwise(pl.col("Threat_Score"))  # [FIX v9.0] Preserve existing Sigma score
            )
            lf = lf.with_columns(score_expr.alias("Chronos_Score"))
        else:
            print("    [!] MFT Timestamps not found. Skipping Standard Timestomp detection.")
            lf = lf.with_columns([
                pl.lit("").alias("Anomaly_Time"),
                pl.lit("").alias("Anomaly_Zero"),
                # [FIX v12.0] Preserve Threat_Score even if timestamps are missing
                pl.col("Threat_Score").alias("Chronos_Score")
            ])
        
        return lf

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

    def _apply_safety_filters(self, df, loader):
        print("    -> [Chronos] Applying Safety Filters (YAML-Driven)...")
        
        available_cols = df.collect_schema().names()
        
        # [v6.7] Unified Noise Filter using ThemisLoader (YAML-Driven)
        is_general_noise = loader.get_noise_filter_expr(available_cols)
        
        # [v6.7] Dual-Use Tool Trap Filter (YAML-Driven)
        is_dual_use_noise = loader.get_dual_use_filter_expr(available_cols)
        
        is_noise = is_general_noise | is_dual_use_noise
        
        # CRITICALタグがついているものはノイズ判定を強制キャンセル
        # [FIX v8.0] 高脅威度タグ (METASPLOIT, COBALT, MIMIKATZ等) もバイパス対象に追加
        is_critical_context = pl.col("Threat_Tag").fill_null("").str.contains("CRITICAL|METASPLOIT|COBALT|MIMIKATZ|EXPLOIT_FRAMEWORK|C2|SLIVER|HAVOC|BCWIPE|CCLEANER")

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

        return df

    def analyze(self, args):
        mode_str = "LEGACY" if args.legacy else "STANDARD"
        print(f"[*] Chronos v3.4 awakening... Mode: {mode_str}")
        try:
            loader = ThemisLoader([
                "rules/triage_rules.yaml",
                "rules/sigma_file_event.yaml",
                "rules/intel_signatures.yaml",
                "rules/sigma_custom.yaml",      # [FIX] Critical tools (Metasploit, Mimikatz)
                "rules/scoring_rules.yaml",     # [FIX] Centralized scoring rules
                "rules/filter_rules.yaml"       # [FIX] Noise filters
            ])
            lf = pl.read_csv(args.file, ignore_errors=True, infer_schema_length=0).lazy()
            
            # [PERF v10.0] MFT Pre-Filtering: Remove System Noise Early
            # This reduces rows before expensive scoring operations
            SYSTEM_NOISE_PATTERN = r"(?i)(\\\\windows\\\\winsxs\\\\|\\\\windows\\\\assembly\\\\|\\\\windows\\\\servicing\\\\|\\\\windows\\\\inf\\\\|\\\\windows\\\\microsoft\.net\\\\|\\\\program files\\\\windowsapps\\\\|\\\\apprepository\\\\|\\\\contentdeliverymanager\\\\|\\\\infusedapps\\\\|deletedalluserpackages)"
            
            # Check which path column exists
            path_col = None
            schema_names = lf.collect_schema().names()
            for candidate in ["ParentPath", "FullPath", "EntryPath"]:
                if candidate in schema_names:
                    path_col = candidate
                    break
            
            if path_col:
                # Keep rows that do NOT match system noise patterns
                lf = lf.filter(~pl.col(path_col).str.contains(SYSTEM_NOISE_PATTERN))
                print(f"    [PERF] Applied MFT pre-filter on '{path_col}' column.")
            
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
            
            # 4. Themis脅威スコアリング (FIRST)
            # [FIX v8.1] Scoring MUST happen BEFORE safety filters
            # so that Threat_Tag is populated for bypass checks
            print("    -> Applying Themis Threat Scoring (Sigma)...")
            lf = loader.apply_threat_scoring(lf)
            
            print("    -> Applying Themis Context Scoring (Skia Rules)...")
            lf = loader.apply_scoring_rules(lf)
            
            # [OPTIMIZED Action 2] Pre-Filtering (Noise Reduction)
            # [FIX v8.1] Now runs AFTER scoring, so high-value tags can bypass
            print("    -> [Optimized] Pre-Filtering Noise (Silverlight, Fontset, etc)...")
            lf = self._apply_safety_filters(lf, loader)
            
            if "Threat_Score" in lf.collect_schema().names():
                lf = lf.with_columns(pl.col("Threat_Score").cast(pl.Int64, strict=False).fill_null(0))

            # 5. コンテキスト判定 (VM同期など)
            lf = self._detect_system_time_context(lf)
            
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
            # [OPTIMIZED v4.1] Use Streaming Engine to prevent Memory Spike
            # [FIX] Updated for Polars 1.25+: streaming -> engine='streaming'
            df = lf.filter(pl.col("Chronos_Score") > 0).collect(engine='streaming')
            import gc
            gc.collect()
            
            # Logic A: Microburst Detection (Update Storm Filter)
            # [FIX] Do NOT force cast SI_CreationTime to Utf8 here. Let _detect_microburst handle it optimally.
            # (以前の強制キャストコードを削除)
            
            df = self._detect_microburst(df, time_col="SI_CreationTime")
            
            # Logic B: Execution Evidence Cross-Check
            # Load Prefetch/Amcache files for alibi check
            prefetch_files = []
            amcache_files = []
            if args.prefetch:
                prefetch_files = [args.prefetch]
            
            # Auto-detect Amcache (Lazy Scan to save init time)
            kape_base = getattr(args, 'kape_dir', None)
            if kape_base:
                from pathlib import Path
                amcache_files = list(Path(kape_base).rglob("*Amcache*.csv"))
            
            df = self._check_execution_evidence(df, prefetch_files=prefetch_files, amcache_files=amcache_files)
            
            # Filter again after Plan B (remove newly zeroed items)
            df = df.filter(pl.col("Chronos_Score") > 0)

            # [OPTIMIZED] Key_Full Generation only when needed
            has_icarus_hits = False
            for res_lazy in icarus_results:
                # Check height without full collect if possible, or perform minimal collect
                # LazyFrame doesn't support height check directly without collect/fetch
                # We collect only relevant columns to check hits
                try:
                    res_df = res_lazy.collect()
                    if res_df.height > 0:
                        has_icarus_hits = True
                        print(f"       [!] Icarus detected {res_df.height} paradoxes!")
                        
                        # Generate Key_Full ONLY if we have hits to merge
                        if "Key_Full" not in df.columns:
                            print("       -> Generating merge keys...")
                            df = df.with_columns(
                                (pl.col("ParentPath").fill_null("").str.to_lowercase().str.replace_all("/", "\\").str.strip_chars("\\") + "\\" + 
                                 pl.col("FileName").fill_null("").str.to_lowercase()).alias("Key_Full")
                            )

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
                except Exception as e:
                    print(f"       [!] Icarus Merge Error: {e}")

            # USNJ Targeted Scan
            if args.usnj and df.height > 0: # Ensure we have suspects
                # Generate Key_Full if not exists (might be skipped if no Icarus hits above)
                if "Key_Full" not in df.columns:
                    # Only generate for suspects if possible, but we need it for join on main df
                    # So generate on main df
                    df = df.with_columns(
                         (pl.col("ParentPath").fill_null("").str.to_lowercase().str.replace_all("/", "\\").str.strip_chars("\\") + "\\" + 
                          pl.col("FileName").fill_null("").str.to_lowercase()).alias("Key_Full")
                    )
                
                suspects = df.filter(pl.col("Chronos_Score") > 50)["Key_Full"].to_list()
                
                if suspects:
                    try:
                        usn_lf = pl.scan_csv(args.usnj, ignore_errors=True, infer_schema_length=0)
                        mft_reuse = df.lazy()
                        
                        # [FIX] Cast timestamps back to String for Icarus compatibility
                        # Icarus expects Strings to perform its own parsing/regex operations.
                        time_cols_fix = ["SI_CreationTime", "StandardInformation_Modified"]
                        # mft_reuse is a LazyFrame from eager DF, so it has concrete schemas.
                        # We must check which columns exist in the eager DF to be safe.
                        existing_cols = df.columns
                        cast_exprs = [pl.col(c).cast(pl.Utf8) for c in time_cols_fix if c in existing_cols]
                        
                        if cast_exprs:
                            mft_reuse = mft_reuse.with_columns(cast_exprs)

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