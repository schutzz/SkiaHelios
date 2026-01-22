import polars as pl
from dataclasses import dataclass
from typing import Optional, List, Dict
from enum import Enum
import logging

# ============================================================
#  SH_IcarusParadox v1.2 [Mythic Edition]
#  Mission: Melt the wax wings of timestompers.
#  Concept: MFT is the Sun. False timestamps are Wax.
# ============================================================

def print_logo():
    print(r"""
       \  :  /
    `.   \ : /   .'    < ICARUS PARADOX >
      `--  * --'      "Wax wings melt before the Truth."
    .'   / : \   `.     v1.2 - Sun & Wax
       /  :  \
    """)

class IcarusDirection(Enum):
    """
    Flight Path Analysis (矛盾の方向性)
    """
    PAST_BACKDATE = "PAST"       # 太陽より低い高度へ (過去偽装)
    FUTURE_FORWARD = "FUTURE"    # 太陽を超えようとする (未来偽装)
    BIDIRECTIONAL = "BOTH"       # 全方位の軌道逸脱

@dataclass
class IcarusConfig:
    """
    イカロスの飛行許容範囲設定
    """
    # 太陽(MFT)との距離の許容誤差（秒）
    tolerance_sec: float = 2.0
    
    # 蝋が溶ける閾値（これ以上離れるとバックデートとみなす秒数）
    melting_point_sec: float = 60.0
    
    # 各アーティファクトの監視方向
    prefetch_direction: IcarusDirection = IcarusDirection.BIDIRECTIONAL
    amcache_direction: IcarusDirection = IcarusDirection.BIDIRECTIONAL
    shimcache_direction: IcarusDirection = IcarusDirection.BIDIRECTIONAL
    usn_direction: IcarusDirection = IcarusDirection.BIDIRECTIONAL

    # 墜落スコア (Severity Scores)
    score_wax_melted: int = 300      # 決定的矛盾 (Prefetch/Amcache)
    score_turbulence: int = 200      # 強い不整合 (ShimCache)
    score_flight_deviation: int = 150 # USN不整合
    score_low_visibility: int = 80   # 信頼度低 (パス未解決など)

class IcarusParadox:
    def __init__(self, config: Optional[IcarusConfig] = None):
        print_logo()
        self.config = config if config else IcarusConfig()
        
        # ロガー設定: 神話的トーンの維持
        self.logger = logging.getLogger("SH.Icarus")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - [ICARUS] - %(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            
        self.logger.info(f"Sun is rising. Melting point set to {self.config.melting_point_sec}s.")

    def _create_robust_key(self, lf: pl.LazyFrame, path_col: str = "ParentPath", name_col: str = "FileName") -> pl.LazyFrame:
        """[Core] Generate Flight ID (Unique Key from Path + Name)"""
        return lf.with_columns(
            pl.concat_str([
                pl.col(path_col).fill_null("").str.to_lowercase().str.replace_all("/", "\\").str.strip_chars("\\"),
                pl.lit("\\"),
                pl.col(name_col).fill_null("").str.to_lowercase()
            ]).alias("Key_Full")
        )

    def _normalize_timestamp(self, lf: pl.LazyFrame, col_name: str, alias: str) -> pl.LazyFrame:
        """Normalize temporal coordinates"""
        return lf.with_columns(
            pl.col(col_name)
            .str.replace("T", " ")
            .str.to_datetime(format="%Y-%m-%d %H:%M:%S%.f", strict=False)
            .alias(alias)
        )

    def _check_trajectory(self, joined: pl.LazyFrame, time_diff_col: str, direction: IcarusDirection, threshold: float) -> pl.LazyFrame:
        """
        [Logic] Check if the file is flying too close to the sun or falling into the sea.
        time_diff = Sun(MFT) - Wax(Artifact)
        """
        if direction == IcarusDirection.PAST_BACKDATE:
            # 差がプラス＝MFTよりArtifactが過去＝バックデート
            return joined.filter(pl.col(time_diff_col) > threshold)
        elif direction == IcarusDirection.FUTURE_FORWARD:
            # 差がマイナス＝MFTよりArtifactが未来＝未来偽装
            return joined.filter(pl.col(time_diff_col) < -threshold)
        else:
            # 両方向の逸脱
            return joined.filter(pl.col(time_diff_col).abs() > threshold)

    def _empty_result(self) -> pl.LazyFrame:
        return pl.LazyFrame({
            "Key_Full": [], "FileName": [], "ParentPath": [],
            "Anomaly_Type": [], "Time_Discrepancy": [], "Icarus_Score": [],
            "Confidence": []
        })

    # [OPTIMIZATION] Cache the prepared MFT (Sun) to avoid re-scanning 160k rows for each artifact.
    _cached_sun_lf: Optional[pl.LazyFrame] = None

    def _prepare_mft_sun(self, mft_lf: pl.LazyFrame) -> pl.LazyFrame:
        """
        [Core Optimization] Materialize the MFT (Sun) once with standardized keys and times.
        Handles column name variations (Created0x10 vs SI_CreationTime).
        Returns a Cached LazyFrame for downstream joins.
        """
        if self._cached_sun_lf is not None:
            return self._cached_sun_lf

        self.logger.info("Preparing Sun (MFT) trajectory engine...")
        schema = mft_lf.collect_schema().names()
        
        # Determine available columns
        fn_col = "FileName"
        path_col = "ParentPath"
        
        # Map time columns (Chronos renamed vs Raw)
        mapping = {}
        
        # Creation
        if "SI_CreationTime" in schema: mapping["Creation"] = "SI_CreationTime"
        elif "Created0x10" in schema: mapping["Creation"] = "Created0x10"
        
        # Modification
        if "StandardInformation_Modified" in schema: mapping["Modification"] = "StandardInformation_Modified"
        elif "LastModified0x10" in schema: mapping["Modification"] = "LastModified0x10"
        elif "LastModified" in schema: mapping["Modification"] = "LastModified"

        # USN Timestamp
        if "Timestamp_UTC" in schema: mapping["USN_Time"] = "Timestamp_UTC"
        elif "Created0x10" in schema: mapping["USN_Time"] = "Created0x10"
        elif "SI_CreationTime" in schema: mapping["USN_Time"] = "SI_CreationTime"

        # Select only necessary columns
        keep_cols = [fn_col, path_col] + list(set(mapping.values()))
        keep_cols = [c for c in keep_cols if c in schema]
        
        lf = mft_lf.select(keep_cols).unique(subset=[path_col, fn_col])
        lf = self._create_robust_key(lf, path_col, fn_col)
        
        # Normalize all mapped time columns
        for key, col in mapping.items():
            if col in keep_cols:
                lf = self._normalize_timestamp(lf, col, f"_sun_{key.lower()}")

        # Materialize/Cache the LazyPlan without full collect
        self._cached_sun_lf = lf.cache()
        return self._cached_sun_lf

    def inspect_prefetch(self, mft_lf: pl.LazyFrame, prefetch_lf: pl.LazyFrame) -> pl.LazyFrame:
        """
        [Witness: Prefetch]
        """
        self.logger.info("Scanning Prefetch formations...")
        try:
            pf_schema = prefetch_lf.collect_schema()
            required = ["LastRun", "FileName", "ParentPath"]
            if any(c not in pf_schema.names() for c in required):
                return self._empty_result()

            # 1. The Sun (MFT) - Cached Lazy
            mft_sun_lf = self._prepare_mft_sun(mft_lf)
            sun_schema = mft_sun_lf.collect_schema().names()
            if "_sun_creation" not in sun_schema:
                self.logger.warning("Missing Creation Time in MFT. Skipping Prefetch Icarus check.")
                return self._empty_result()

            mft_sun = mft_sun_lf.select(["Key_Full", "_sun_creation", "FileName", "ParentPath"])

            # 2. Wax Wings (Prefetch)
            pf_wings = self._create_robust_key(prefetch_lf)
            pf_wings = self._normalize_timestamp(pf_wings, "LastRun", "_wax_time")
            pf_wings = pf_wings.select(["Key_Full", "_wax_time"])

            # 3. Collision Course
            joined = pf_wings.join(mft_sun, on="Key_Full", how="inner")
            
            # _time_diff = Sun - Wax. 
            joined = joined.with_columns(
                (pl.col("_sun_creation") - pl.col("_wax_time")).dt.total_seconds().alias("_time_diff")
            )

            crashed = self._check_trajectory(
                joined, "_time_diff", self.config.prefetch_direction, self.config.melting_point_sec
            )

            return crashed.with_columns([
                pl.lit("ICARUS_PREFETCH_MELTED").alias("Anomaly_Type"),
                pl.col("_time_diff").alias("Time_Discrepancy"),
                pl.lit(self.config.score_wax_melted).alias("Icarus_Score"),
                pl.lit("HIGH").alias("Confidence")
            ])
        except Exception as e:
            self.logger.error(f"Prefetch scan failed: {e}")
            return self._empty_result()

    def inspect_shimcache(self, mft_lf: pl.LazyFrame, shim_lf: pl.LazyFrame) -> pl.LazyFrame:
        """
        [Witness: ShimCache]
        """
        self.logger.info("Scanning ShimCache residue...")
        try:
            if "LastModified" not in shim_lf.collect_schema().names():
                return self._empty_result()

            # 1. The Sun (MFT) - Cached Lazy
            mft_sun_lf = self._prepare_mft_sun(mft_lf)
            sun_schema = mft_sun_lf.collect_schema().names()
            if "_sun_modification" not in sun_schema:
                 self.logger.warning("Missing Modification Time in MFT. Skipping ShimCache Icarus check.")
                 return self._empty_result()

            mft_sun = mft_sun_lf.select(["Key_Full", "_sun_modification", "FileName", "ParentPath"])

            shim_wings = self._create_robust_key(shim_lf)
            shim_wings = self._normalize_timestamp(shim_wings, "LastModified", "_wax_mod")
            shim_wings = shim_wings.select(["Key_Full", "_wax_mod"])

            joined = shim_wings.join(mft_sun, on="Key_Full", how="inner")
            
            joined = joined.with_columns(
                (pl.col("_sun_modification") - pl.col("_wax_mod")).dt.total_seconds().alias("_time_diff")
            )

            crashed = self._check_trajectory(
                joined, "_time_diff", self.config.shimcache_direction, self.config.tolerance_sec
            )

            return crashed.with_columns([
                pl.lit("ICARUS_SHIMCACHE_TURBULENCE").alias("Anomaly_Type"),
                pl.col("_time_diff").alias("Time_Discrepancy"),
                pl.lit(self.config.score_turbulence).alias("Icarus_Score"),
                pl.lit("HIGH").alias("Confidence")
            ])
        except Exception as e:
            self.logger.error(f"ShimCache scan failed: {e}")
            return self._empty_result()

    def inspect_usnj_safe(self, mft_lf: pl.LazyFrame, usnj_lf: pl.LazyFrame, suspects: List[str]) -> pl.LazyFrame:
        """
        [Witness: USN Journal]
        Targeted flight path analysis.
        Safe mode enabled: No MFT culling, fallback handling for missing paths.
        """
        if not suspects:
            return self._empty_result()

        self.logger.info(f"Tracking flight paths for {len(suspects)} suspects in USN...")
        
        try:
            # [FIX v1.5] Use Cached Sun (MFT) Lazy
            mft_sun_lf = self._prepare_mft_sun(mft_lf)
            sun_schema = mft_sun_lf.collect_schema().names()
            if "_sun_usn_time" not in sun_schema:
                 self.logger.warning("[!] No universal time column found in MFT (Sun). Aborting USN check.")
                 return self._empty_result()

            mft_sun = mft_sun_lf.select(["Key_Full", "FileName", "ParentPath", "_sun_usn_time"])
            
            # [FIX v1.3] Name normalization
            usn_cols = usnj_lf.collect_schema().names()
            if "Name" in usn_cols and "FileName" not in usn_cols:
                usnj_lf = usnj_lf.rename({"Name": "FileName"})
            
            # [FIX v1.4] USN timestamp column detection
            usn_time_col = None
            for candidate in ["UpdateTimestamp", "Timestamp", "UpdateTime"]:
                if candidate in usn_cols:
                    usn_time_col = candidate
                    break
            
            if not usn_time_col:
                self.logger.warning("[!] No valid timestamp column in USN source. Aborting.")
                return self._empty_result()

            # 2. Filter USN by Name first (Performance)
            suspect_names = [s.split("\\")[-1].lower() for s in suspects]
            usn_track = usnj_lf.filter(
                pl.col("FileName").str.to_lowercase().is_in(suspect_names)
            )
            usn_track = self._normalize_timestamp(usn_track, usn_time_col, "_wax_time")

            # Check for Path availability
            usn_cols = usn_track.collect_schema().names()
            path_col = "ParentPath" if "ParentPath" in usn_cols else ("Path" if "Path" in usn_cols else None)

            # 3. Intercept
            if path_col:
                # Precise interception
                usn_keyed = self._create_robust_key(usn_track, path_col=path_col)
                joined = usn_keyed.join(mft_sun, on="Key_Full", how="inner")
                joined = joined.with_columns(pl.lit("HIGH").alias("Confidence"))
            else:
                # Blind interception (Fallback)
                # Note: mft_sun has FileName
                self.logger.warning("[!] Visibility low: USN lacks path. Engaging wide-area search (Name Match Only).")
                joined = usn_track.join(mft_sun, on="FileName", how="inner")
                joined = joined.with_columns(pl.lit("LOW").alias("Confidence"))
            
            # 4. Impact Calculation (Use _sun_usn_time)
            joined = joined.with_columns(
                (pl.col("_sun_usn_time") - pl.col("_wax_time")).dt.total_seconds().alias("_time_diff")
            )

            crashed = self._check_trajectory(
                joined, "_time_diff", self.config.usn_direction, self.config.melting_point_sec
            )

            # Assign Scores based on visibility
            crashed = crashed.with_columns([
                pl.lit("ICARUS_USN_DEVIATION").alias("Anomaly_Type"),
                pl.col("_time_diff").alias("Time_Discrepancy"),
                pl.when(pl.col("Confidence") == "HIGH")
                  .then(self.config.score_flight_deviation)
                  .otherwise(self.config.score_low_visibility)
                  .alias("Icarus_Score")
            ])

            # Ensure Key_Full exists for result consistency
            if "Key_Full" not in crashed.collect_schema().names():
                 crashed = self._create_robust_key(crashed)

            return crashed

        except Exception as e:
            self.logger.error(f"USN tracking failed: {e}")
            return self._empty_result()