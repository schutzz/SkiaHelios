import polars as pl

# ============================================================
#  SH_HestiaCensorship v2.0 [Precision Strike]
#  Mission: Centralized Noise Censorship & "Zone of Death" Logic.
#  Update: Added specific noise paths for Tor, HashSuite, Jetico.
# ============================================================

class Hestia:
    """
    聖域の門番。ノイズと判断されたアーティファクトを容赦なく検閲する。
    """
    def __init__(self):
        # 1. 死の領域 (Zone of Death) - 部分一致(contains)で判定
        # ここに含まれるパスを持つファイルは、原則として削除対象
        self.death_zones = [
            # Standard Trash
            "/inetcache/", "/inetcookies/", "/appdata/local/history/", 
            "/appdata/local/temp/", "/windows/temp/", 
            "/localservice/appdata/", "/networkservice/appdata/",
            "/auth/logon.html", "google/chrome/user data",
            "microsoft/windows/notifications",
            
            # [NEW] Tool-specific Noise (Samples, Fonts, Libs)
            "hash_suite_free/reports", "hash_suite_free/samples", 
            "hash_suite_free/wordlists", "hash_suite_free/docs",
            "hash_suite_free/lang", "hash_suite_free/phrases",
            "tor browser/browser/fonts", "tor browser/browser/dictionaries",
            "jetico/shared", "jetico/bcwipe/help",
            
            # System Noise
            "programdata/microsoft/office/uicaptions",
            "program files/common files/microsoft shared",
            "windows/servicing", "windows/winsxs",
            "windows/assembly", "windows/microsoft.net",
            "windows/system32/driverstore"
        ]

        # 2. ゴミ拡張子 (Trash Extensions) - 場所に関わらず怪しい
        self.trash_exts = [
            ".pyc", ".tmp", ".msi", ".cab", ".ico", ".css", ".map", 
            ".qml", ".rom", ".bin", ".dat", ".log", ".etl", ".swidtag",
            ".pnf", ".cur", ".nls", ".mum", ".cat", ".inf",
            ".ttf", ".dic", ".cap", ".pcap" # [NEW] Added specific artifact noise
        ]

        # 3. 聖域 (Sanctuary) - 死の領域にあっても救済する拡張子
        # (例: Tempフォルダ内の実行ファイルなど)
        self.executable_exts = [
            ".exe", ".dll", ".ps1", ".bat", ".vbs", ".cmd", ".js", ".wsf", ".lnk", ".crx"
        ]

    def apply_censorship(self, df, path_col, filename_col=None, correlation_col=None):
        """
        検閲を実行し、生存者のみを含むDataFrameを返す（フィルタリング済み）。
        """
        print(f"    -> [Hestia] Judging {df.height} artifacts...")
        
        # 1. 正規化パスの作成 (lower + forward slash)
        if filename_col:
            df = df.with_columns(
                pl.concat_str([pl.col(path_col), pl.lit("/"), pl.col(filename_col)])
                .str.to_lowercase()
                .str.replace_all(r"\\", "/")
                .alias("_hestia_path")
            )
        else:
            df = df.with_columns(
                pl.col(path_col)
                .str.to_lowercase()
                .str.replace_all(r"\\", "/")
                .alias("_hestia_path")
            )

        # 2. 判定ロジック構築
        
        # A. 死の領域にいるか？
        is_in_death_zone = pl.lit(False)
        for zone in self.death_zones:
            is_in_death_zone = is_in_death_zone | pl.col("_hestia_path").str.contains(zone, literal=True)

        # B. ゴミ拡張子か？
        is_trash_ext = pl.lit(False)
        for ext in self.trash_exts:
            is_trash_ext = is_trash_ext | pl.col("_hestia_path").str.ends_with(ext)

        # C. 実行可能ファイルか？ (免罪符)
        is_executable = pl.lit(False)
        for ext in self.executable_exts:
            is_executable = is_executable | pl.col("_hestia_path").str.ends_with(ext)

        # D. 相関があるか？ (最強の免罪符)
        if correlation_col and correlation_col in df.columns:
            # Pandora v18.5で Int64(1/0) に統一済み
            is_correlated = (pl.col(correlation_col) == 1)
        else:
            is_correlated = pl.lit(False)

        # 3. 判決 (Verdict)
        # 基本ルール: 死の領域またはゴミ拡張子なら削除。ただし、実行ファイルか相関があれば生存。
        should_kill = (is_in_death_zone | is_trash_ext) & (~is_executable) & (~is_correlated)

        # 4. 執行 (Filter)
        survivors = df.filter(~should_kill)
        
        print(f"    -> [Hestia] Purged {df.height - survivors.height} noise artifacts.")
        return survivors.drop("_hestia_path")

def main():
    print("[*] SH_HestiaCensorship is a library module.")

if __name__ == "__main__":
    main()