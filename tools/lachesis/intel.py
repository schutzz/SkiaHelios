import re
import yaml
from pathlib import Path
from tools.SH_ThemisLoader import ThemisLoader

TEXT_RES = {
    "en": { "title": "Incident Report", "cats": {} },
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
    }
}

class LachesisIntel:
    def __init__(self, base_dir="."):
        self.loader = ThemisLoader(["rules/triage_rules.yaml"])
        self.dual_use_keywords = self.loader.get_dual_use_keywords()
        self.noise_stats = {}
        self.intel_sigs = self._load_intel_signatures()

    def _load_intel_signatures(self):
        """Load Intelligence Signatures from YAML"""
        # Note: Correcting path assumption relative to this module
        # Assuming structure: tools/lachesis/intel.py -> need to go up to project root -> rules/
        sig_path = Path(__file__).parent.parent.parent / "rules" / "intel_signatures.yaml"
        sigs = []
        if sig_path.exists():
            try:
                with open(sig_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "signatures" in data:
                        sigs = data["signatures"]
            except Exception as e:
                print(f"    [!] Failed to load intel signatures: {e}")
        return sigs

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
        trusted_roots = [
            "c:/windows/", "c:/program files/", "c:/program files (x86)/",
            "{windows}", "{system32}", "{program files", "{common program files"
        ]
        suspicious_subdirs = ["/temp", "/tmp", "/users/public", "/appdata", "/programdata", "downloads", "documents", "desktop"]
        if any(s in p for s in suspicious_subdirs): return False
        return any(root in p for root in trusted_roots)

    def is_noise(self, name, path=""):
        name = str(name).strip().lower()
        path = str(path).strip().lower().replace("\\", "/")
        garbage_paths = [
            "appdata/local/google/chrome", "appdata/roaming/microsoft/spelling",
            "appdata/roaming/skype", "appdata/local/packages", 
            "windows/assembly", "windows/servicing", "windows/prefetch", 
            "inetcache", "tkdata", "thumbcache", "iconcache",
            "windows/notifications", "appdata/local/microsoft/windows/notifications"
        ]
        for gp in garbage_paths:
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