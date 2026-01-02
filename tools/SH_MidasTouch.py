import os
import sys
import re
import hashlib
import shutil
import subprocess
import json
import zipfile
import datetime
import argparse
from pathlib import Path

# ============================================================
#  SH_MidasTouch v1.4 [Executive Font Engine]
#  Mission: Transform Markdown into Executive Reports (Docx/PDF).
#  Features:
#    - Dual Font Rendering (Times New Roman + Yu Mincho) (NEW!)
#    - Auto-Detect "Reference.docx" in Project Root
#    - Organized Output (Midas_Artifacts)
#    - Mermaid Auto-Render & Team Sync Mode
# ============================================================

class MidasTouch:
    def __init__(self, input_md_path):
        self.input_md = Path(input_md_path).resolve()
        self.root_dir = self.input_md.parent
        
        # --- フォルダ構成 ---
        self.midas_dir = self.root_dir / "Midas_Artifacts"
        self.cache_dir = self.midas_dir / ".cache"
        self.assets_dir = self.midas_dir / "assets"
        self.sync_dir = self.midas_dir / "TEAM_SYNC_PACK"
        
        self.mmdc_cmd = self._find_tool("mmdc")
        self.pandoc_cmd = self._find_tool("pandoc")
        
        self.midas_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.assets_dir.mkdir(parents=True, exist_ok=True)

    def _find_tool(self, tool_name):
        path = shutil.which(tool_name)
        if path is None and os.name == 'nt':
            path = shutil.which(f"{tool_name}.cmd")
        return path

    def _calculate_hash(self, content):
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _render_mermaid(self, mermaid_code, code_hash):
        output_filename = f"diag_{code_hash}.png"
        output_img = self.assets_dir / output_filename
        if output_img.exists(): return output_img
        if not self.mmdc_cmd: return None

        temp_mmd = self.cache_dir / f"{code_hash}.mmd"
        with open(temp_mmd, "w", encoding="utf-8") as f:
            f.write(mermaid_code)

        try:
            cmd = [self.mmdc_cmd, "-i", str(temp_mmd), "-o", str(output_img), "-b", "transparent", "-s", "2"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return output_img
        except: return None

    def _preprocess_markdown(self):
        try:
            with open(self.input_md, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(self.input_md, "r", encoding="utf-8-sig") as f:
                content = f.read()

        pattern = re.compile(r'```mermaid\n(.*?)```', re.DOTALL)
        def replacement(match):
            code = match.group(1)
            img_path = self._render_mermaid(code, self._calculate_hash(code))
            if img_path:
                rel_path = os.path.relpath(img_path, self.midas_dir)
                return f"![Architecture Diagram]({rel_path})"
            return match.group(0)

        new_content = pattern.sub(replacement, content)
        processed_md = self.midas_dir / f"{self.input_md.stem}_midas_proc.md"
        with open(processed_md, "w", encoding="utf-8") as f:
            f.write(new_content)
        return processed_md

    def convert_to_docx(self, reference_docx=None):
        """
        メイン処理：MD -> Docx 変換 (フォント打ち分けオプション追加)
        """
        print(f"[*] MidasTouch: Converting {self.input_md.name} to Docx...")
        if not self.pandoc_cmd: return False

        # --- Reference Doc & Font Logic ---
        final_ref = None
        if reference_docx:
            final_ref = Path(reference_docx)
        else:
            project_root = Path(__file__).resolve().parent.parent
            candidate = project_root / "Reference.docx"
            if candidate.exists():
                final_ref = candidate
                print(f"    [i] Auto-detected Reference Style: {final_ref.name}")

        target_md = self._preprocess_markdown()
        output_docx = self.midas_dir / f"{self.input_md.stem}_Report.docx"
        
        # --- Pandoc Command Construction ---
        cmd = [self.pandoc_cmd, str(target_md), "-o", str(output_docx)]
        
        if final_ref:
            cmd.extend(["--reference-doc", str(final_ref)])
        
        # 🦁 ここが「英数字: Times New Roman / 日本語: 游明朝」の打ち分け設定っス！
        # Note: 環境にフォントがない場合は標準フォントにフォールバックされるっス。
        cmd.extend([
            "-V", "mainfont:Times New Roman",  # 英数字は伝統のTimes
            "-V", "CJKmainfont:MS Mincho"      # 日本語は鉄板のMS明朝
        ])
            
        try:
            subprocess.run(cmd, check=True, cwd=self.midas_dir)
            print(f"    [+] Generated: {output_docx}")
            return True
        except Exception as e:
            print(f"[!] Pandoc Failed: {e}")
            return False

    def enable_team_sync(self, case_name, investigator_name="Unknown"):
        print(f"\n[*] MidasTouch: Initiating TEAM SYNC MODE...")
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        zip_path = self.sync_dir / f"SkiaHelios_Evidence_Package_{case_name}.zip"
        manifest = {"Case": case_name, "Investigator": investigator_name, "Generated_At": datetime.datetime.now().isoformat(), "Files": {}}

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for csv_file in self.root_dir.rglob("*.csv"):
                parent_name = csv_file.parent.name if csv_file.parent.name != self.root_dir.name else "Root"
                arcname = f"Evidence_Data/{parent_name}/{csv_file.name}"
                zf.write(csv_file, arcname)
                with open(csv_file, "rb") as f:
                    manifest["Files"][arcname] = hashlib.sha256(f.read()).hexdigest()

            for mmd_file in self.cache_dir.glob("*.mmd"):
                zf.write(mmd_file, f"Visuals/Source_Code/{mmd_file.name}")

            for docx in self.midas_dir.glob("*_Report.docx"):
                zf.write(docx, f"Final_Report/{docx.name}")

            zf.writestr("manifest.json", json.dumps(manifest, indent=4))
        print(f"    [+] TEAM SYNC PACKAGE SEALED: {zip_path}")

def main(argv=None):
    parser = argparse.ArgumentParser(description="SH_MidasTouch")
    parser.add_argument("input", help="Input Markdown file")
    parser.add_argument("ref_doc", nargs="?", help="Reference Docx Path")
    args = parser.parse_args(argv)
    
    midas = MidasTouch(args.input)
    if midas.convert_to_docx(args.ref_doc):
        case_name = Path(args.input).stem.replace("Grimoire_", "").replace("_jp", "").replace("_en", "")
        midas.enable_team_sync(case_name, "Senpai")

if __name__ == "__main__":
    main(sys.argv[1:])