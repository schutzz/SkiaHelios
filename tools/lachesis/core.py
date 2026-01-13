from pathlib import Path
import traceback
from tools.lachesis.intel import LachesisIntel
from tools.lachesis.enricher import LachesisEnricher
from tools.lachesis.sh_analyzer import LachesisAnalyzer
from tools.lachesis.renderer import LachesisRenderer

try:
    from tools.SH_TartarosTracer import TartarosTracer
except ImportError:
    TartarosTracer = None

class LachesisCore:
    def __init__(self, lang="jp", hostname="Unknown_Host", case_name="Investigation", base_dir="."):
        self.lang = lang
        self.hostname = hostname
        self.case_name = case_name
        self.base_dir = Path(base_dir)
        self.intel = LachesisIntel(base_dir)
        self.enricher = LachesisEnricher(base_dir)
        self.analyzer = LachesisAnalyzer(self.intel, self.enricher, lang=self.lang)

    def weave_report(self, analysis_result, output_path, dfs_for_ioc, hostname, os_info, primary_user, history_csv=None, history_search_path=None):
        print(f"[*] Lachesis v4.50 (Refactored) is weaving the report into {output_path}...")
        self.hostname = hostname 
        real_os_info = self.enricher.resolve_os_info_fallback(os_info, Path(output_path).parent)
        analysis_data = self.analyzer.process_events(analysis_result, dfs_for_ioc)
        
        origin_stories = []
        if self.analyzer.pivot_seeds and TartarosTracer:
            timeline_df = dfs_for_ioc.get("Timeline")
            df_history_target = self.enricher.resolve_history_df(dfs_for_ioc)
            if not history_csv and df_history_target is None:
                search_roots = [Path(output_path).parent, Path(".")]
                if history_search_path: search_roots.insert(0, Path(history_search_path))
                history_csv = self.enricher.auto_find_history_csv(search_roots, dfs_for_ioc)

            if history_csv or timeline_df is not None or df_history_target is not None:
                try:
                    tracer = TartarosTracer(history_csv=history_csv)
                    origin_stories = tracer.trace_memory(self.analyzer.pivot_seeds, timeline_df, df_history=df_history_target)
                except: pass

        renderer = LachesisRenderer(output_path, self.lang)
        metadata = {"hostname": hostname, "os_info": real_os_info, "primary_user": primary_user}
        renderer.render_report(analysis_data, self.analyzer, self.enricher, origin_stories, dfs_for_ioc, metadata)
        
        json_path = Path(output_path).with_suffix('.json')
        pivot_path = Path(output_path).parent / "Pivot_Config.json"
        renderer.export_json_grimoire(analysis_result, self.analyzer, json_path, primary_user)
        renderer.export_pivot_config(self.analyzer.pivot_seeds, pivot_path, primary_user)