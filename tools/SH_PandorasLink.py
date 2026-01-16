import polars as pl
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from tools.SH_ThemisLoader import ThemisLoader

# ============================================================
#  SH_PandorasLink v18.20 [Ransomware Hunter]
#  Mission: Surgical removal, Cross-Correlation & Ransomware Detection.
#  Update: A.1 Encryption Burst Detection (Polars集計)
# ============================================================

# Ransomware Extension List (Configurable)
RANSOMWARE_EXTENSIONS = [
    ".encrypted", ".lock", ".crypt", ".crypto", ".cerber", ".zepto", ".locky",
    ".odin", ".aesir", ".osiris", ".thor", ".loptr", ".sage", ".wallet",
    ".wncry", ".wcry", ".wnry", ".wannacry", ".ransomware", ".petya",
    ".notpetya", ".gandcrab", ".ryuk", ".sodinokibi", ".revil", ".conti",
    ".lockbit", ".blackcat", ".hive", ".akira", ".rhysida", ".babuk"
]

def print_logo():
    logo = r"""
      .       +    .    * .      .
    .    _    .    ______    .    _    .
       _/ \_   _  / ____ \  _   _/ \_
      /     \ / \/ /    \ \/ \ /     \
     /_     _\   | |    | |   /_     _\
       \   / \_  \ \____/ /   _/ \   /
    * \_/    \__\______/__/    \_/   *
      .     * /______\     .     .
    
      [ SH_PandorasLink v18.17 ]
     "The Trinity: Normalized & Focused."
    """
    print(logo)

class PandoraEngine:
    def __init__(self, mft_live, usn, mft_vss=None, triage_mode=False):
        self.mft_live_path = mft_live
        self.usn_path = usn
        self.mft_vss_path = mft_vss
        self.triage_mode = triage_mode
        self.loader = ThemisLoader([
            "rules/triage_rules.yaml", 
            "rules/sigma_file_event.yaml", 
            "rules/intel_signatures.yaml",
            "rules/sigma_custom.yaml"  # [Custom Rules] Metasploit, Impacket, etc.
        ])
        print(f"[*] Initializing Engine with Themis Rules...")
        self.lf_live = self._load_mft(mft_live).lazy()
        self.lf_usn = self._load_usn(usn).lazy()
        self.lf_vss = self._load_mft(mft_vss).lazy() if mft_vss else None

    def _get_col_expr(self, cols, targets, alias=None):
        for t in targets:
            if t in cols:
                expr = pl.col(t)
                if alias: expr = expr.alias(alias)
                return expr
        return None

    def _robust_date_parse(self, col_expr):
        return pl.coalesce([
            col_expr.str.to_datetime("%Y-%m-%d %H:%M:%S%.f", strict=False),
            col_expr.str.to_datetime("%Y-%m-%d %H:%M:%S", strict=False),
            col_expr.str.to_datetime("%m/%d/%Y %H:%M:%S", strict=False),
            col_expr.str.to_datetime("%d/%m/%Y %H:%M:%S", strict=False)
        ])

    def _load_mft(self, path):
        try:
            try: lf_schema = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
            except: lf_schema = pl.scan_csv(path, encoding='utf-8-sig', ignore_errors=True, infer_schema_length=0)
            cols = lf_schema.collect_schema().names()
            exprs = []
            e_num = self._get_col_expr(cols, ["EntryNumber", "MftRecordNumber"])
            if e_num is not None: exprs.append(e_num.cast(pl.Int64))
            seq_num = self._get_col_expr(cols, ["FileSequenceNumber", "SequenceNumber"], "FileSequenceNumber")
            if seq_num is not None: exprs.append(seq_num.cast(pl.Int64))
            in_use = self._get_col_expr(cols, ["InUse", "IsAllocated"], "Live_InUse")
            if in_use is not None: exprs.append(in_use)
            fname = self._get_col_expr(cols, ["FileName", "Name"], "Live_FileName")
            if fname is not None: exprs.append(fname)
            ppath = self._get_col_expr(cols, ["ParentPath", "ParentFolder"], "Live_ParentPath")
            if ppath is not None: exprs.append(ppath)
            created = self._get_col_expr(cols, ["StandardInformation_Created", "Created0x10", "SI_Created"], "StandardInformation_Created")
            if created is not None: exprs.append(created)
            fsize = self._get_col_expr(cols, ["FileSize", "Size"], "Live_FileSize")
            if fsize is not None: exprs.append(fsize.cast(pl.Int64))
            return lf_schema.select(exprs)
        except Exception as e:
            print(f"[!] Error loading MFT {path}: {e}")
            raise RuntimeError(f"Failed to load MFT")

    def _load_usn(self, path):
        try:
            lf_schema = pl.scan_csv(path, ignore_errors=True, infer_schema_length=0)
            cols = lf_schema.collect_schema().names()
            exprs = []
            e_num = self._get_col_expr(cols, ["EntryNumber", "MftRecordNumber"])
            if e_num is not None: exprs.append(e_num.cast(pl.Int64))
            seq_num = self._get_col_expr(cols, ["FileSequenceNumber", "SequenceNumber"], "FileSequenceNumber")
            if seq_num is not None: exprs.append(seq_num.cast(pl.Int64))
            p_enum = self._get_col_expr(cols, ["ParentEntryNumber", "ParentFileReferenceNumber", "ParentFrn"], "ParentEntryNumber")
            if p_enum is not None: exprs.append(p_enum.cast(pl.Int64))
            reason = self._get_col_expr(cols, ["UpdateReasons", "UpdateReason", "Reasons"], "UpdateReason")
            if reason is not None: exprs.append(reason)
            ts = self._get_col_expr(cols, ["UpdateTimestamp", "TimeStamp", "Timestamp"], "TimeStamp")
            if ts is not None: exprs.append(ts)
            fname = self._get_col_expr(cols, ["FileName", "Name", "Filename"], "FileName")
            if fname is not None: exprs.append(fname)
            ppath = self._get_col_expr(cols, ["ParentPath", "ParentFolder"])
            if ppath is not None: exprs.append(ppath)
            return lf_schema.select(exprs)
        except Exception as e:
            print(f"[!] Error loading USN {path}: {e}")
            raise RuntimeError(f"Failed to load USN")

    def correlate_cross_evidence(self, df_ghosts, chronos_csv, hercules_csv):
        print("[*] Phase 3.5: Cross-Correlating with The Trinity...")
        
        df_ghosts = df_ghosts.with_columns(
            pl.concat_str([pl.col("ParentPath"), pl.lit("/"), pl.col("Ghost_FileName")])
            .str.to_lowercase().str.replace_all(r"\\", "/").str.replace(r"^\./", "")
            .alias("Ghost_Key")
        )

        df_ghosts = df_ghosts.with_columns([
            pl.lit(0).alias("Chronos_Boost"),
            pl.lit(0).alias("Herc_Boost")
        ])

        if chronos_csv and os.path.exists(chronos_csv):
            try:
                print(f"    -> Correlating with Chronos: {chronos_csv}")
                df_chronos = pl.read_csv(chronos_csv, ignore_errors=True, infer_schema_length=0)
                if "FileName" in df_chronos.columns:
                    df_chronos = df_chronos.filter(pl.col("Chronos_Score").cast(pl.Int64, strict=False) > 50)
                    df_chronos = df_chronos.with_columns(
                        pl.concat_str([pl.col("ParentPath"), pl.lit("/"), pl.col("FileName")])
                        .str.to_lowercase().str.replace_all(r"\\", "/").str.replace(r"^\./", "")
                        .alias("Chronos_Key")
                    ).select(["Chronos_Key"]).unique()
                    
                    df_ghosts = df_ghosts.join(df_chronos, left_on="Ghost_Key", right_on="Chronos_Key", how="left")
                    df_ghosts = df_ghosts.with_columns(
                        pl.when(pl.col("Chronos_Key").is_not_null())
                        .then(150).otherwise(pl.col("Chronos_Boost")).alias("Chronos_Boost")
                    ).drop("Chronos_Key")
            except: pass

        if hercules_csv and os.path.exists(hercules_csv):
            try:
                print(f"    -> Correlating with Hercules: {hercules_csv}")
                df_herc = pl.read_csv(hercules_csv, ignore_errors=True, infer_schema_length=0)
                if "Target_Path" in df_herc.columns:
                    df_herc = df_herc.filter(pl.col("Judge_Verdict").str.contains("CRITICAL"))
                    df_herc = df_herc.with_columns(
                        pl.col("Target_Path").str.to_lowercase().str.replace_all(r"\\", "/").alias("Herc_Key")
                    ).select(["Herc_Key"]).unique()
                    
                    df_ghosts = df_ghosts.join(df_herc, left_on="Ghost_Key", right_on="Herc_Key", how="left")
                    df_ghosts = df_ghosts.with_columns(
                        pl.when(pl.col("Herc_Key").is_not_null())
                        .then(200).otherwise(pl.col("Herc_Boost")).alias("Herc_Boost")
                    ).drop("Herc_Key")
            except: pass

        df_ghosts = df_ghosts.with_columns(
            (pl.col("Threat_Score") + pl.col("Chronos_Boost") + pl.col("Herc_Boost")).alias("Threat_Score")
        )
        
        df_ghosts = df_ghosts.with_columns(
            pl.when((pl.col("Chronos_Boost") > 0) | (pl.col("Herc_Boost") > 0))
            .then(pl.concat_str([pl.col("Threat_Tag"), pl.lit(",CORRELATED")]))
            .otherwise(pl.col("Threat_Tag"))
            .alias("Threat_Tag")
        )
        
        # Zone of Death
        is_web_trash = pl.col("Ghost_Key").str.contains(r"/inetcache/|/inetcookies/|/history/|/temp/")
        is_hash_suite_noise = (pl.col("Ghost_Key").str.contains("hash_suite_free") & (~pl.col("Ghost_Key").str.ends_with(".exe")))
        
        has_correlation = (pl.col("Chronos_Boost") > 0) | (pl.col("Herc_Boost") > 0)
        should_die = (is_web_trash | is_hash_suite_noise) & (~has_correlation)
        
        df_ghosts = df_ghosts.with_columns([
            pl.when(should_die).then(pl.lit("NOISE_ARTIFACT")).otherwise(pl.col("Threat_Tag")).alias("Threat_Tag"),
            pl.when(should_die).then(0).otherwise(pl.col("Threat_Score")).alias("Threat_Score")
        ])

        return df_ghosts.drop(["Ghost_Key", "Chronos_Boost", "Herc_Boost"])

    def _apply_logic_layer(self, df):
        print("    -> [Pandora] Applying Masquerade & Noise Logic (Inverted Tool Filter)...")
        
        df = df.with_columns([
            pl.col("ParentPath").fill_null("").str.to_lowercase().alias("_pp"),
            pl.col("Ghost_FileName").fill_null("").str.to_lowercase().alias("_fn")
        ])
        
        # Normalize Path
        df = df.with_columns(
            pl.concat_str([pl.col("_pp"), pl.lit("/"), pl.col("_fn")])
            .str.replace_all(r"\\", "/")
            .alias("_full_path")
        )

        # ==========================================
        # 🔨 SLEDGEHAMMER (Files to Kill)
        # ==========================================
        file_kill_list = [
            "safe browsing", "bistats.lock", ".qml", 
            "edb.log", "edb00", "thumbs.db", "iconcache", 
            "gdipfontcache", "ntuser.dat", "usrclass.dat"
        ]
        
        # [NEW] Triage Mode Extension (Cleaner)
        if self.triage_mode:
            print("       >> [!] Triage Mode: Aggressive Junk Killing Active")
            file_kill_list.extend([
                ".ldb", "-journal", ".sys", ".lst", ".cab", ".pyd", 
                "0000", ".lock", ".log",
                ".aux", ".bmp", ".gif", ".rbf", ".ni.dll", "mcafee.truekey"
            ])
        
        # [Fix] AppX Noise Filter (Global) - Moved from Triage block
        file_kill_list.extend([
            "microsoft_ppiprojection", "appup.intelgraphicsexperience", "microsoft.windows.cortana",
             "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}_windowspowershell_v1_0_powershell_ise_exe",
             "{d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27}_windowspowershell_v1_0_powershell_ise_exe"
        ])
        
        path_kill_list = [
            "dropbox", "onedrive", "assembly", "servicing",
            "microsoft.net", "windowsapps", "winsxs",
            "windows/filemanager/assets",
            "macromedia", "flash player", "sharedobjects", # Flash junk
            "appdata/local/packages", "appdata\\local\\packages", # Appx junk
            "templates" # Office junk
        ]

        # ==========================================
        # ⚡ DUAL-USE TRAP (Inverted Logic)
        # ==========================================
        dual_use_folders = [
            "nmap", "wireshark", "python", "tcl", "ruby", "perl", "java", "jdk", "jre"
        ]
        
        protected_binaries = [
            "nmap.exe", "zenmap.exe", "ncat.exe", 
            "wireshark.exe", "tshark.exe", "capinfos.exe", "dumpcap.exe",
            "python.exe", "pythonw.exe", "pip.exe",
            "java.exe", "javaw.exe", "javac.exe",
            "ruby.exe", "perl.exe"
        ]

        is_noise = pl.lit(False)
        for kw in file_kill_list:
            is_noise = is_noise | pl.col("_fn").str.contains(kw, literal=True)
            
        for kw in path_kill_list:
            # 救済措置: Pathがマッチしても、拡張子が .exe, .crx, .lnk なら殺さない
            is_match = pl.col("_full_path").str.contains(kw, literal=True)
            is_protected = pl.col("_fn").str.ends_with(".exe") | pl.col("_fn").str.ends_with(".crx") | pl.col("_fn").str.ends_with(".lnk") | pl.col("_fn").str.ends_with(".bat")
            is_noise = is_noise | (is_match & ~is_protected)

        # Apply Inverted Logic
        is_tool_folder = pl.lit(False)
        for tool in dual_use_folders:
            is_tool_folder = is_tool_folder | pl.col("_full_path").str.contains(tool, literal=True)
        
        is_protected_binary = pl.col("_fn").is_in(protected_binaries)
        is_noise = is_noise | (is_tool_folder & (~is_protected_binary))

        # 既存のロジック用 Normalized Path
        df = df.with_columns(
            pl.concat_str([pl.col("ParentPath"), pl.lit("/"), pl.col("Ghost_FileName")])
            .str.to_lowercase()
            .str.replace_all(r"\\", "/")
            .str.replace(r"^\./", "")
            .alias("Normalized_Path")
        )

        is_adobe_masquerade = (pl.col("Normalized_Path").str.contains("adobe") & pl.col("Normalized_Path").str.ends_with(".crx"))
        is_lnk_phish = (pl.col("Normalized_Path").str.ends_with(".lnk") & (pl.col("Normalized_Path").str.contains(r"\.jpg\.lnk|\.pdf\.lnk|\.doc\.lnk") | pl.col("Normalized_Path").str.contains(r"cute|cat|kitten|invoice|urgent|receipt|payment|hqdefault|promo|crop")))
        is_skype_xml = (pl.col("Ghost_FileName").str.to_lowercase() == "shared.xml")
        is_hash_cracker = (pl.col("Normalized_Path").str.contains("hash_suite_free") & pl.col("Normalized_Path").str.ends_with(".exe"))
        is_wiper = ((pl.col("Normalized_Path").str.contains("bcwipe") | pl.col("Normalized_Path").str.contains("jetico")) & pl.col("Normalized_Path").str.ends_with(".exe"))

        # [NEW] YAML Noise Rules Integration
        dynamic_noise_expr = self.loader.get_noise_filter_expr(df.collect_schema().names())
        
        should_kill = (is_noise | dynamic_noise_expr) & (~is_adobe_masquerade) & (~is_lnk_phish) & (~is_skype_xml) & (~is_hash_cracker) & (~is_wiper)
        
        tag_expr = pl.col("Threat_Tag")
        score_expr = pl.col("Threat_Score")

        tag_expr = pl.when(should_kill).then(pl.lit("NOISE_ARTIFACT")).otherwise(tag_expr)
        score_expr = pl.when(should_kill).then(0).otherwise(score_expr)

        tag_expr = pl.when(is_adobe_masquerade).then(pl.lit("CRITICAL_MASQUERADE")).otherwise(tag_expr)
        score_expr = pl.when(is_adobe_masquerade).then(300).otherwise(score_expr)

        tag_expr = pl.when(is_lnk_phish).then(pl.lit("CRITICAL_PHISHING")).otherwise(tag_expr)
        score_expr = pl.when(is_lnk_phish).then(250).otherwise(score_expr)
        
        tag_expr = pl.when(is_hash_cracker).then(pl.lit("CREDENTIAL_DUMP_TOOL")).otherwise(tag_expr)
        score_expr = pl.when(is_hash_cracker).then(200).otherwise(score_expr)

        tag_expr = pl.when(is_wiper).then(pl.lit("DATA_WIPER_TOOL")).otherwise(tag_expr)
        score_expr = pl.when(is_wiper).then(150).otherwise(score_expr)

        tag_expr = pl.when(is_skype_xml).then(pl.lit("SUSPICIOUS_XML")).otherwise(tag_expr)
        score_expr = pl.when(is_skype_xml).then(50).otherwise(score_expr)

        # ==========================================
        # 📚 1. Resource File Strict Path Verification
        # ==========================================
        # Use regex for efficiency instead of loop
        is_resource = pl.col("Normalized_Path").str.contains(r"\.(mui|nls|lng|template|provxml)$")
        # Check if in System32 or SysWOW64 (Authorized Zones)
        is_sys_path = pl.col("Normalized_Path").str.contains(r"windows/system32", literal=True) | pl.col("Normalized_Path").str.contains(r"windows/syswow64", literal=True)
        
        # Logic: Kill resource files in System paths (noise). Do NOT boost non-system resources.
        should_kill_resource = is_resource & is_sys_path
        
        tag_expr = pl.when(should_kill_resource).then(pl.lit("NOISE_RESOURCE")).otherwise(tag_expr)
        score_expr = pl.when(should_kill_resource).then(0).otherwise(score_expr)
        
        # [FIX] Also kill resource files from common app locations (not DLL sideloading)
        is_app_resource = is_resource & (
            pl.col("Normalized_Path").str.contains("program files", literal=True) |
            pl.col("Normalized_Path").str.contains("programdata", literal=True) |
            pl.col("Normalized_Path").str.contains("appdata/local/", literal=True)
        )
        tag_expr = pl.when(is_app_resource).then(pl.lit("NOISE_RESOURCE")).otherwise(tag_expr)
        score_expr = pl.when(is_app_resource).then(0).otherwise(score_expr)

        # ==========================================
        # 🌐 2. Browser Cache Isolation
        # ==========================================
        is_browser_cache = pl.col("Normalized_Path").str.contains(r"/cache/|/inetcache/|/temporary internet files/")
        # Use regex for efficiency
        is_web_content = pl.col("Normalized_Path").str.contains(r"\.(jpg|png|gif|css|js|json|txt|ico)$")
        recon_keywords = ["phishing", "admin", "dashboard", "c2", "payload", "setup", "install"]
        is_recon = pl.col("Normalized_Path").str.contains("|".join(recon_keywords))
        
        should_kill_browser = is_browser_cache & is_web_content & (~is_recon)
        
        tag_expr = pl.when(should_kill_browser).then(pl.lit("NOISE_BROWSER")).otherwise(tag_expr)
        score_expr = pl.when(should_kill_browser).then(0).otherwise(score_expr)
        
        tag_expr = pl.when(is_browser_cache & is_recon).then(pl.lit("INTERNAL_RECON_WEB")).otherwise(tag_expr)
        score_expr = pl.when(is_browser_cache & is_recon).then(600).otherwise(score_expr)

        # ==========================================
        # 💀 3. Dictionary of Doom (Dual-Use Floor)
        # ==========================================
        # [DISABLED for performance - v6.2 logic moved to sh_analyzer.py THREAT_BOOST_PATTERNS]
        # The boost is now applied at Analyzer level, not Polars expression level.

        # ==========================================
        # 🔎 4. Sensitive Data Heuristics
        # ==========================================
        # [DISABLED for performance - v6.2 logic moved to sh_analyzer.py SENSITIVE_KEYWORDS]
        # The boost is now applied at Analyzer level.


        # [NEW] Network Share / Lateral Movement Detection (Case 5 Enhanced)
        # 1. UNC Paths - Exclude local \\?\ and \\.\ prefixes and localhost
        is_unc_path = (
            pl.col("ParentPath").str.starts_with(r"\\") & 
            (~pl.col("ParentPath").str.starts_with("\\\\?\\")) &
            (~pl.col("ParentPath").str.starts_with("\\\\.\\")) &
            (~pl.col("ParentPath").str.contains(r"\\localhost")) &
            (~pl.col("ParentPath").str.contains(r"\\127.0.0.1"))
        )
        
        # [NEW] Target_Path Check (for LNKs)
        cols = df.collect_schema().names()
        is_unc_target = pl.col("Target_Path").str.starts_with(r"\\") if "Target_Path" in cols else pl.lit(False)
        
        # 2. Mapped Drives
        is_mapped_drive = pl.col("Normalized_Path").str.contains(r"^[a-z]:/").and_(~pl.col("Normalized_Path").str.starts_with("c:/"))
        
        # 3. Specific Threat: Putty/SSH/SetMACE in User Folders
        is_putty = pl.col("Normalized_Path").str.contains(r"putty|winscp|ssh|pscp") & pl.col("Normalized_Path").str.ends_with(".exe")
        is_setmace = pl.col("Normalized_Path").str.contains("setmace")
        is_choco = pl.col("Normalized_Path").str.contains("chocolatey") & pl.col("Normalized_Path").str.ends_with(".exe")

        is_remote_lateral = (is_unc_path | is_unc_target | is_mapped_drive) & (pl.col("Normalized_Path").str.ends_with(".exe") | pl.col("Normalized_Path").str.ends_with(".lnk"))

        # Scoring & Tagging
        tag_expr = pl.when(is_remote_lateral).then(pl.concat_str([pl.lit("LATERAL_MOVEMENT_EXEC"), tag_expr], separator=",")).otherwise(tag_expr)
        score_expr = pl.when(is_remote_lateral).then(score_expr + 150).otherwise(score_expr)
        
        tag_expr = pl.when(is_putty).then(pl.concat_str([pl.lit("REMOTE_ACCESS_TOOL"), tag_expr], separator=",")).otherwise(tag_expr)
        score_expr = pl.when(is_putty).then(score_expr + 100).otherwise(score_expr)

        tag_expr = pl.when(is_setmace).then(pl.lit("CRITICAL_TIMESTOMP_TOOL")).otherwise(tag_expr)
        score_expr = pl.when(is_setmace).then(400).otherwise(score_expr)

        tag_expr = pl.when(is_choco).then(pl.concat_str([pl.lit("PKG_MANAGER_ABUSE"), tag_expr], separator=",")).otherwise(tag_expr)
        score_expr = pl.when(is_choco).then(score_expr + 50).otherwise(score_expr)

        return df.with_columns([
            tag_expr.alias("Threat_Tag"),
            score_expr.alias("Threat_Score")
        ]).drop(["Normalized_Path", "_pp", "_fn", "_full_path"])

    def run_gap_analysis_full(self, start_date, end_date):
        print("[*] Phase 1: Running Physical Gap Analysis...")
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        except: return None

        ghosts_list = []
        if self.lf_vss is not None:
            try:
                q_vss = self.lf_vss.rename({
                    "Live_FileName": "Ghost_FileName", "FileSequenceNumber": "VSS_SeqNum",
                    "StandardInformation_Created": "Ghost_Time_Hint", "Live_ParentPath": "ParentPath"
                })
                ghost_vss = q_vss.join(
                    self.lf_live, left_on=["EntryNumber", "VSS_SeqNum"], right_on=["EntryNumber", "FileSequenceNumber"], how="anti"
                ).select(["EntryNumber", "Ghost_FileName", "ParentPath", "Ghost_Time_Hint"]).with_columns(pl.lit("VSS_Gap").alias("Source"))
                ghosts_list.append(ghost_vss)
            except: pass

        usn_with_date = self.lf_usn.with_columns(self._robust_date_parse(pl.col("TimeStamp")).alias("Parsed_Date"))
        q_usn_del = usn_with_date.filter((pl.col("Parsed_Date").is_between(start_dt, end_dt)) & (pl.col("UpdateReason").str.contains("FileDelete")))
        ghost_usn = q_usn_del.join(self.lf_live, on="EntryNumber", how="left", suffix="_Live").filter(
            (pl.col("FileSequenceNumber") != pl.col("FileSequenceNumber_Live")) | (pl.col("Live_InUse") == False) | (pl.col("FileSequenceNumber_Live").is_null())
        )
        if "ParentEntryNumber" in ghost_usn.collect_schema().names():
            parent_lookup = self.lf_live.select([pl.col("EntryNumber").alias("P_Entry"), pl.col("Live_ParentPath").alias("GrandParentPath"), pl.col("Live_FileName").alias("ParentName")])
            ghost_usn = ghost_usn.join(parent_lookup, left_on="ParentEntryNumber", right_on="P_Entry", how="left")
            reconstructed_path = pl.concat_str([pl.col("GrandParentPath"), pl.lit("\\"), pl.col("ParentName")])
            ghost_usn = ghost_usn.with_columns(pl.col("ParentPath").fill_null(reconstructed_path).alias("ParentPath"))

        ghost_usn = ghost_usn.select(["EntryNumber", "FileName", "ParentPath", "Parsed_Date"]).rename({"FileName": "Ghost_FileName", "Parsed_Date": "Ghost_Time_Hint"}).with_columns(pl.lit("USN_Trace").alias("Source"))
        ghosts_list.append(ghost_usn)

        if not ghosts_list: return None
        combined_ghosts = pl.concat(ghosts_list).unique(subset=["EntryNumber", "Ghost_FileName"])
        
        combined_ghosts = combined_ghosts.with_columns(pl.col("Ghost_FileName").alias("FileName"))
        scored_ghosts = self.loader.apply_threat_scoring(combined_ghosts)
        scored_ghosts = self._apply_logic_layer(scored_ghosts)
        return scored_ghosts

    def run_anti_forensics(self, limit=50): return pl.LazyFrame([])

    def run_necromancer(self, lf_ghosts, pf_csv=None, shim_csv=None, chaos_csv=None):
        """
        [Necromancer v2.0] Resurrect execution evidence by correlating Ghost files
        with Prefetch, ShimCache, and ChaosGrasp (UserAssist) data.
        
        Enriches ghosts with:
          - Prefetch Run Count
          - ShimCache presence (execution evidence)
          - UserAssist Run Counter
        """
        print("    -> [Necromancer] Correlating execution artifacts...")
        
        # Ensure we have FileName column for matching
        schema = lf_ghosts.collect_schema().names()
        if "Ghost_FileName" not in schema:
            print("       [!] No Ghost_FileName column, skipping Necromancer")
            return lf_ghosts
        
        # Create normalized join key
        lf_ghosts = lf_ghosts.with_columns(
            pl.col("Ghost_FileName").str.to_lowercase().str.replace_all(r"\\", "/").alias("_necro_key")
        )
        
        # Initialize enrichment columns
        lf_ghosts = lf_ghosts.with_columns([
            pl.lit(None).cast(pl.Int64).alias("PF_Run_Count"),
            pl.lit(None).cast(pl.Int64).alias("UA_Run_Count"),
            pl.lit(False).alias("Shim_Evidence")
        ])
        
        # 1. Prefetch Correlation
        if pf_csv and os.path.exists(pf_csv):
            try:
                print(f"       -> Loading Prefetch: {pf_csv}")
                df_pf = pl.read_csv(pf_csv, ignore_errors=True, infer_schema_length=0)
                # Column variations: ExecutableName, SourceFilename, etc.
                pf_name_col = None
                for col in ["ExecutableName", "SourceFilename", "FileName", "Name"]:
                    if col in df_pf.columns:
                        pf_name_col = col
                        break
                pf_run_col = None
                for col in ["RunCount", "Run Count", "PrefetchCount"]:
                    if col in df_pf.columns:
                        pf_run_col = col
                        break
                
                if pf_name_col and pf_run_col:
                    df_pf = df_pf.select([
                        pl.col(pf_name_col).str.to_lowercase().alias("_pf_key"),
                        pl.col(pf_run_col).cast(pl.Int64, strict=False).alias("PF_Run_Count_Val")
                    ]).unique(subset=["_pf_key"])
                    
                    lf_ghosts = lf_ghosts.join(
                        df_pf.lazy(), left_on="_necro_key", right_on="_pf_key", how="left"
                    ).with_columns(
                        pl.coalesce([pl.col("PF_Run_Count_Val"), pl.col("PF_Run_Count")]).alias("PF_Run_Count")
                    ).drop(["PF_Run_Count_Val"])
                    print(f"       [+] Prefetch matched!")
            except Exception as e:
                print(f"       [!] Prefetch load error: {e}")
        
        # 2. ShimCache Correlation
        if shim_csv and os.path.exists(shim_csv):
            try:
                print(f"       -> Loading ShimCache: {shim_csv}")
                df_shim = pl.read_csv(shim_csv, ignore_errors=True, infer_schema_length=0)
                # Column variations
                shim_path_col = None
                for col in ["Path", "CachePath", "ControlSet001Path", "Key"]:
                    if col in df_shim.columns:
                        shim_path_col = col
                        break
                
                if shim_path_col:
                    # Extract filename from full path
                    df_shim = df_shim.with_columns(
                        pl.col(shim_path_col).str.to_lowercase().str.extract(r"([^\\]+)$", 1).alias("_shim_key")
                    ).select(["_shim_key"]).unique()
                    
                    lf_ghosts = lf_ghosts.join(
                        df_shim.lazy(), left_on="_necro_key", right_on="_shim_key", how="left"
                    ).with_columns(
                        pl.when(pl.col("_shim_key").is_not_null()).then(True).otherwise(pl.col("Shim_Evidence")).alias("Shim_Evidence")
                    ).drop(["_shim_key"])
                    print(f"       [+] ShimCache matched!")
            except Exception as e:
                print(f"       [!] ShimCache load error: {e}")
        
        # 3. ChaosGrasp / UserAssist Correlation
        if chaos_csv and os.path.exists(chaos_csv):
            try:
                print(f"       -> Loading ChaosGrasp: {chaos_csv}")
                df_chaos = pl.read_csv(chaos_csv, ignore_errors=True, infer_schema_length=0)
                # UserAssist columns
                ua_name_col = None
                for col in ["Target_FileName", "FileName", "Application"]:
                    if col in df_chaos.columns:
                        ua_name_col = col
                        break
                ua_count_col = None
                for col in ["Run Count", "RunCounter", "Count"]:
                    if col in df_chaos.columns:
                        ua_count_col = col
                        break
                
                if ua_name_col and ua_count_col:
                    df_chaos = df_chaos.select([
                        pl.col(ua_name_col).str.to_lowercase().alias("_ua_key"),
                        pl.col(ua_count_col).cast(pl.Int64, strict=False).alias("UA_Run_Count_Val")
                    ]).unique(subset=["_ua_key"])
                    
                    lf_ghosts = lf_ghosts.join(
                        df_chaos.lazy(), left_on="_necro_key", right_on="_ua_key", how="left"
                    ).with_columns(
                        pl.coalesce([pl.col("UA_Run_Count_Val"), pl.col("UA_Run_Count")]).alias("UA_Run_Count")
                    ).drop(["UA_Run_Count_Val"])
                    print(f"       [+] UserAssist matched!")
            except Exception as e:
                print(f"       [!] ChaosGrasp load error: {e}")
        
        # Apply execution evidence boost
        has_execution = (
            pl.col("PF_Run_Count").is_not_null() |
            pl.col("UA_Run_Count").is_not_null() |
            pl.col("Shim_Evidence")
        )
        
        lf_ghosts = lf_ghosts.with_columns([
            pl.when(has_execution).then(pl.col("Threat_Score") + 100).otherwise(pl.col("Threat_Score")).alias("Threat_Score"),
            pl.when(has_execution).then(pl.concat_str([pl.col("Threat_Tag"), pl.lit(",EXECUTION_EVIDENCE")])).otherwise(pl.col("Threat_Tag")).alias("Threat_Tag")
        ])
        
        return lf_ghosts.drop(["_necro_key"])

    def detect_encryption_burst(self, threshold_count: int = 50, threshold_seconds: int = 60):
        """
        [A.1] Ransomware Encryption Burst Detection
        
        MFT/USNデータフレームから暗号化バースト（短時間での大量ファイル生成）を検知する。
        
        Args:
            threshold_count: バーストとみなす最小ファイル数 (default: 50)
            threshold_seconds: バーストとみなす最大継続時間（秒） (default: 60)
            
        Returns:
            pl.DataFrame with detected burst events
        """
        print(f"[*] Ransomware Burst Detection: Scanning for {threshold_count}+ files in {threshold_seconds}s...")
        
        results = []
        
        # User領域パスフィルタ (システム領域のノイズ除去)
        user_path_regex = r"(?i)(\\Users\\[^\\]+\\(Documents|Desktop|Pictures|Music|Downloads|Videos|OneDrive|Dropbox))"
        
        try:
            # USN Journal を使用（リアルタイムに近いタイムスタンプ）
            lf_usn = self.lf_usn.with_columns(
                self._robust_date_parse(pl.col("TimeStamp")).alias("Parsed_Timestamp")
            )
            
            # 拡張子を抽出
            lf_usn = lf_usn.with_columns(
                pl.col("FileName").str.to_lowercase().str.extract(r"(\.[a-z0-9]+)$", 1).alias("Extension")
            )
            
            # ランサムウェア拡張子にマッチするエントリを抽出
            ransom_entries = lf_usn.filter(
                pl.col("Extension").is_in(RANSOMWARE_EXTENSIONS)
            )
            
            # ParentPath がある場合、ユーザー領域でフィルタ
            if "ParentPath" in lf_usn.collect_schema().names():
                ransom_entries = ransom_entries.filter(
                    pl.col("ParentPath").str.contains(user_path_regex)
                )
            
            # 集計: 拡張子ごとに最初と最後のタイムスタンプ、ファイル数をカウント
            burst_candidates = (
                ransom_entries
                .group_by("Extension")
                .agg([
                    pl.count().alias("file_count"),
                    pl.min("Parsed_Timestamp").alias("start_time"),
                    pl.max("Parsed_Timestamp").alias("end_time"),
                    pl.col("FileName").head(5).alias("sample_files")
                ])
            ).collect()
            
            # バースト判定: Naive Approach (全体の時間差でチェック)
            for row in burst_candidates.iter_rows(named=True):
                file_count = row["file_count"]
                start_time = row["start_time"]
                end_time = row["end_time"]
                extension = row["Extension"]
                sample_files = row["sample_files"]
                
                if start_time is None or end_time is None:
                    continue
                    
                duration = (end_time - start_time).total_seconds()
                
                if file_count >= threshold_count and duration <= threshold_seconds:
                    results.append({
                        "Timestamp": str(start_time),
                        "Extension": extension,
                        "File_Count": file_count,
                        "Duration_Seconds": duration,
                        "Sample_Files": ", ".join(sample_files) if sample_files else "",
                        "Verdict": "CRITICAL_RANSOMWARE_BURST",
                        "Score": min(file_count * 10, 1000),  # Cap at 1000
                        "Description": f"Detected {file_count} files with extension {extension} created in {duration:.1f}s"
                    })
                    print(f"    [!] BURST DETECTED: {file_count} x '{extension}' in {duration:.1f}s")
                elif file_count >= threshold_count // 2:
                    # Low Burst: Half threshold (still worth noting)
                    results.append({
                        "Timestamp": str(start_time),
                        "Extension": extension,
                        "File_Count": file_count,
                        "Duration_Seconds": duration,
                        "Sample_Files": ", ".join(sample_files) if sample_files else "",
                        "Verdict": "SUSPICIOUS_ENCRYPTION_ACTIVITY",
                        "Score": min(file_count * 5, 500),
                        "Description": f"Detected {file_count} files with extension {extension}"
                    })
                    print(f"    [~] Suspicious activity: {file_count} x '{extension}'")
                    
        except Exception as e:
            print(f"    [-] Burst Detection Error: {e}")
            
        if results:
            print(f"    [+] Ransomware Burst Detection: {len(results)} events found!")
            return pl.DataFrame(results)
        else:
            print(f"    [-] Ransomware Burst Detection: No bursts detected.")
            return pl.DataFrame()

def auto_detect_ntfs(target_dir):
    target = Path(target_dir)
    found = {"mft": None, "usn": None}
    mft_candidates = list(target.rglob("*$MFT_Output.csv")) or list(target.rglob("*MFT.csv"))
    if mft_candidates: found["mft"] = mft_candidates[0]
    usn_candidates = list(target.rglob("*$J_Output.csv")) or list(target.rglob("*UsnJrnl.csv"))
    if usn_candidates: found["usn"] = usn_candidates[0]
    return found

def main(argv=None):
    print_logo()
    parser = argparse.ArgumentParser(description="SH_PandorasLink v18.17")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--dir", help="Auto-detect CSVs")
    group.add_argument("--manual", action="store_true")
    parser.add_argument("--mft"); parser.add_argument("--usn"); parser.add_argument("--vss")
    parser.add_argument("--start", required=True); parser.add_argument("--end", required=True)
    parser.add_argument("--chaos"); parser.add_argument("--pf"); parser.add_argument("--shim")
    parser.add_argument("--chronos", help="Chronos CSV for Correlation")
    parser.add_argument("--hercules", help="Hercules CSV for Correlation")
    parser.add_argument("--out", default="pandora_result_v18.17.csv")
    
    # [NEW] Triage Flag
    parser.add_argument("--triage", action="store_true", help="Enable Aggressive Junk Killer")
    args = parser.parse_args(argv)
    
    mft_path = args.mft
    usn_path = args.usn
    if args.dir:
        detected = auto_detect_ntfs(args.dir)
        if not mft_path: mft_path = detected["mft"]
        if not usn_path: usn_path = detected["usn"]
    if not mft_path or not usn_path: return
    
    try:
        engine = PandoraEngine(str(mft_path), str(usn_path), args.vss, triage_mode=args.triage)
        lf_ghosts = engine.run_gap_analysis_full(args.start, args.end)
        
        if lf_ghosts is not None:
            df_ghosts = lf_ghosts.collect()
            df_ghosts = engine.correlate_cross_evidence(df_ghosts, args.chronos, args.hercules)
            df_ghosts = df_ghosts.with_columns(pl.col("Threat_Tag").alias("Risk_Tag"))

            print(f"[*] Final Filtering (Threshold > 50)...")
            df_result = df_ghosts.filter(pl.col("Threat_Score") > 50)
            df_result = df_result.sort("Threat_Score", descending=True)
            
            if df_result.height > 0:
                df_result.write_csv(args.out)
                print(f"[+] GHOSTS: {df_result.height} records (Cleaned).")
            else:
                print("[-] No ghosts found.")
                df_ghosts.head(0).write_csv(args.out)
                
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()