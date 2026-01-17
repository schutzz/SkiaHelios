import json
import re
import polars as pl
import os
from datetime import datetime, timedelta
from pathlib import Path
from tools.lachesis.intel import TEXT_RES

from tools.lachesis.narrator import NarrativeGenerator
from tools.lachesis.user_reporter import UserActivityReporter

# [NEW] Jinja2 Integration
try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("    [!] Jinja2 not found. Lachesis Renderer requires jinja2.")
    Environment = None

class LachesisRenderer:
    def __init__(self, output_path, lang="jp"):
        self.output_path = output_path
        self.lang = lang if lang in TEXT_RES else "jp"
        self.txt = TEXT_RES[self.lang]
        self.hostname = "Unknown"
        self.template_env = None
        
        # Setup Jinja2
        if Environment:
            try:
                # Use resolve() to get absolute path regardless of execution context
                base_dir = Path(__file__).resolve().parent
                template_dir = base_dir / "templates"
                if not template_dir.exists():
                    print(f"    [!] Template directory not found: {template_dir}")
                else:
                    self.template_env = Environment(loader=FileSystemLoader(str(template_dir)))
            except Exception as e:
                print(f"    [!] Jinja2 Setup Failed: {e}")

        # Setup Narrative Engine
        try:
            # Path: tools/lachesis/renderer.py -> tools/lachesis/ -> SkiaHelios/rules/narrative_templates.yaml
            root_dir = Path(__file__).resolve().parent.parent.parent
            narrative_path = root_dir / "rules" / "narrative_templates.yaml"
            self.narrator = NarrativeGenerator(str(narrative_path))
        except Exception as e:
            print(f"    [!] Narrative Engine Setup Failed: {e}")
            self.narrator = None

    # ... (render_report method remains same until _generate_tech_narrative)

    def _generate_tech_narrative(self, ioc, all_iocs):
        """
        [Narrator] Generates human-readable explanation using Hybrid approach:
        1. NarrativeGenerator (YAML Templates) for static definitions.
        2. Dynamic logic for context correlation (e.g. PowerShell ISE).
        """
        narrative = ""
        
        # 1. Try Template Engine First
        if self.narrator:
            narrative = self.narrator.resolve(ioc)
        
        # 2. Dynamic Correlation Logic (Enhancements)
        tag = str(ioc.get("Tag", ""))
        val = str(ioc.get("Value", "") or ioc.get("Target_Path", "") or ioc.get("FileName", ""))
        
        # Fallback if Template didn't match ADS but we know it is ADS (Safety Net / Hybrid)
        if not narrative and ("ADS" in tag or "MASQUERADE" in tag):
             # Basic Manual Fallback (if YAML missing)
             narrative = f"### 🛡️ 隠蔽工作 (Defense Evasion: ADS)\nDetected ADS Masquerading: `{val}`"

        # ADS Correlation: PowerShell ISE
        if "ADS" in tag or "MASQUERADE" in tag:
            has_ise = any("PowerShell_ISE" in str(i.get("Value", "")) or "PowerShell_ISE" in str(i.get("Target_Path", "")) for i in all_iocs)
            if has_ise:
                ise_note = "\n\n⚠️ **Context**: 直近で `PowerShell_ISE.exe` の実行痕跡が確認されており、このツールを用いてADSが作成された可能性があります。"
                if narrative: narrative += ise_note

        return narrative

    # ═══════════════════════════════════════════════════════════
    # [NEW] Display Data Beautification
    # ═══════════════════════════════════════════════════════════
    def _clean_display_data(self, iocs):
        """
        [Fix] Beautify data for reporting.
        - Deduplicate tags
        - Remove internal system tags (MFT, USN, Single Letters)
        - Truncate long paths to fit in markdown tables
        """
        cleaned = []
        # Tags to hide from the final report
        HIDDEN_TAGS = [
            "MFT_ENTRY", "USN_ENTRY", "PROXIMITY_BOOST", "CORRELATED", "LIVE", 
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", 
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "_"
        ]
        
        for ioc in iocs:
            new_ioc = ioc.copy()
            
            # 1. Clean Tags
            raw_tags = str(new_ioc.get('Tag', '')).replace(' ', '').split(',')
            # Filter, Deduplicate, and Sort
            visible_tags = sorted(list(set([t for t in raw_tags if t and t not in HIDDEN_TAGS and len(t) > 1])))
            
            if visible_tags:
                new_ioc['Tag'] = ", ".join(visible_tags[:3])  # Limit to top 3
            else:
                new_ioc['Tag'] = "-"
            
            # 2. Smart Truncate Path/Value
            val = str(new_ioc.get('Value', ''))
            # Only truncate if extremely long
            if len(val) > 60:
                parts = val.replace('/', '\\').split('\\')
                if len(parts) > 3:
                    # Keep ellipsis, parent folder, filename
                    new_ioc['Value'] = f"...\\{parts[-2]}\\{parts[-1]}"
                else:
                    new_ioc['Value'] = val[:30] + "..." + val[-25:]
            
            cleaned.append(new_ioc)
        return cleaned

    def render_report(self, analysis_data, analyzer, enricher, origin_stories, dfs_for_ioc, metadata):
        """
        Render report using Jinja2 template.
        Prepares all necessary context variables and passes them to the template.
        """
        self.hostname = metadata.get("hostname", "Unknown")
        out_file = self.output_path
        
        # Debug Log File
        log_file = Path(out_file).parent / "renderer_debug_log.txt"
        with open(log_file, "a", encoding="utf-8") as log:
            log.write(f"\n[{datetime.now()}] Starting render_report for {out_file}\n")
        
        print(f"[*] Lachesis v6.5 (Grimoire Engine) is weaving the Grimoire into {out_file}...")

        if not self.template_env:
            msg = "    [!] Critical: Jinja2 environment not initialized."
            print(msg)
            with open(log_file, "a", encoding="utf-8") as log: log.write(msg + "\n")
            return

        # 1. Prepare Context Data
        try:
            # [User Request] Apply USN Condenser to Timeline Phases (Section 3)
            # This fixes the "USN Storm" in the Detailed Timeline table.
            if analysis_data and 'phases' in analysis_data:
                # ═══════════════════════════════════════════════════════════
                # Context-Aware Scoring (Root Cause Fix) - Phase Timeline
                # Uses unified adjust_score() for FN/FP balanced filtering
                # ═══════════════════════════════════════════════════════════
                from tools.lachesis.sh_analyzer import LachesisAnalyzer
                
                PHASE_DISPLAY_THRESHOLD = 50  # Same as IOC section
                
                filtered_phases = []
                for phase in analysis_data['phases']:
                    filtered_phase = []
                    for ev in phase:
                        summary = str(ev.get('Summary', ''))
                        # [FIX] Populate Path from multiple possible sources
                        path = str(ev.get('Path', '')) or str(ev.get('Full_Path', '')) or str(ev.get('Value', '')) or summary
                        ev['Path'] = path  # Ensure Path is set on the event for template
                        original_score = int(ev.get('Score', 0)) if ev.get('Score') else 0
                        
                        # [Grimoire v6.3/v6.4] Image Hygiene for Timeline
                        path_lower = path.lower().replace("/", "\\")
                        fname = path_lower.split("\\")[-1]
                        tags = str(ev.get('Tag', '')).upper()
                        
                        # Extended noise extensions
                        noise_exts = [".mui", ".nls", ".dll", ".sys", ".jpg", ".png", ".gif", ".ico", ".xml", ".dat"]
                        
                        # Extended system paths
                        system_resource_paths = [
                            "windows\\system32", "windows\\syswow64", "windows\\web\\",
                            "windows\\branding\\", "program files\\windowsapps",
                        ]
                        browser_cache_paths = [
                            "appdata\\local\\microsoft\\windows\\inetcache",
                            "temporary internet files", "content.ie5",
                        ]
                        
                        # Evidence Shield keywords
                        RECON_KEYWORDS = ["xampp", "phpmyadmin", "admin", "dashboard", "kibana", "phishing", "c2", "login"]
                        
                        if any(fname.endswith(ext) for ext in noise_exts):
                            # Recon keywords protect images
                            if any(fname.endswith(ie) for ie in [".png", ".jpg", ".gif", ".ico"]):
                                if any(kw in path_lower for kw in RECON_KEYWORDS):
                                    pass  # Keep as evidence
                                elif any(sp in path_lower for sp in system_resource_paths):
                                    continue  # Drop
                                elif any(bp in path_lower for bp in browser_cache_paths):
                                    continue  # Drop
                            # MUI/NLS/DLL/SYS files in system paths
                            elif any(sp in path_lower for sp in system_resource_paths) and "RECON" not in tags:
                                continue  # Skip this event
                        
                        # Apply Context-Aware Score Adjustment
                        command_line = str(ev.get('CommandLine', '')) or str(ev.get('cmdline', ''))
                        adjusted_score, new_tags = analyzer.adjust_score(path, original_score, command_line=command_line)
                        
                        # Update event with adjusted score
                        ev['Score'] = adjusted_score
                        
                        # Keep if above threshold
                        if adjusted_score >= PHASE_DISPLAY_THRESHOLD:
                            filtered_phase.append(ev)
                    
                    # Only add non-empty phases
                    if filtered_phase:
                        # Apply USN condensation after filtering
                        condensed = self._condense_usn_events(filtered_phase)
                        filtered_phases.append(condensed)
                
                analysis_data['phases'] = filtered_phases


            # [Optimization] Global Noise Reduction ( The Reaper & Kaishaku )
            # Applies Score Adjustment, Tagging, and Noise Filtering BEFORE Grouping.
            # This ensures Section 4 (Tables), Section 7 (IOCs), and Timeline are consistent.
            from tools.lachesis.sh_analyzer import LachesisAnalyzer
            DISPLAY_THRESHOLD = 50
            
            cleaned_iocs = []
            print(f"[DEBUG-FLOW] Starting Global Cleaning. Input IOCs: {len(analyzer.visual_iocs)}")

            for ioc in analyzer.visual_iocs:
                # 1. Path Calculation
                path = str(ioc.get("Path", ""))
                value = str(ioc.get("Value", ""))
                target_path = path if path else value
                
                # 2. Score Adjustment & Tagging
                original_score = int(ioc.get("Score", 0) or 0)
                command_line = str(ioc.get("CommandLine", "")) or str(ioc.get('cmdline', ''))
                adjusted_score, new_tags = analyzer.adjust_score(target_path, original_score, analyzer.path_penalties, command_line=command_line)
                
                ioc["Score"] = adjusted_score
                ioc["Original_Score"] = original_score
                
                if new_tags:
                    existing = str(ioc.get("Tag", ""))
                    ioc["Tag"] = existing + "," + ",".join(new_tags) if existing else ",".join(new_tags)

                # 3. [The Reaper] Final Noise Filter
                if "SYSTEM_NOISE" in str(ioc.get("Tag", "")) and adjusted_score < 400:
                    continue 

                # 4. [Nuclear Option] TIMESTOMP Score Threshold
                # User Order: "Forget old logic. Score < 500 = Drop."
                ioc_type = str(ioc.get("Type", "")).upper()
                ioc_cat = str(ioc.get("Category", "")).upper()
                if "TIMESTOMP" in ioc_type or "TIMESTOMP" in ioc_cat:
                    if adjusted_score < 500:
                        continue

                # 5. Threshold Check
                if adjusted_score >= DISPLAY_THRESHOLD:
                    cleaned_iocs.append(ioc)

            # 6. Grouping and Preparation
            refined_iocs = self._group_all_iocs(cleaned_iocs, analyzer)
            print(f"[DEBUG-FLOW] Global Cleaning Complete. Refined IOCs: {len(refined_iocs)}")

            # [Fix] Global Clean of VOID bug
            for ioc in refined_iocs:
                t_str = str(ioc.get('Time', ''))
                if "VOID_VISUALIZA" in t_str: 
                     ioc['Time'] = "-"

            # [Fix] Pre-calculate technical findings using CLEANED IOCs
            tech_findings = self._prepare_technical_findings_from_list(refined_iocs, analyzer, origin_stories)
            init_access = tech_findings.get("INITIAL ACCESS", [])
            high_lnks = [i for i in init_access if i.get("Insight")]
            gen_lnks = [i for i in init_access if not i.get("Insight")]
            
            # Since filtering is already done, scored_iocs is just refined_iocs
            scored_iocs = refined_iocs
            
            context = {
                "txt": self.txt,
                "hostname": self.hostname,
                "metadata": metadata,
                "analysis_data": analysis_data,
                "now": datetime.now().strftime('%Y-%m-%d'),
                "dynamic_verdict": analyzer.get_verdict_for_report(analysis_data.get("verdict_flags")),
                "attack_methods": self._get_attack_methods(analyzer),
                
                # [CHANGE] Replace the old vertical flowchart with the new Sequence Diagram
                # Old: self._render_mermaid_vertical_clustered(refined_iocs)
                # New: self._render_attack_chain_mermaid(refined_iocs)
                "mermaid_timeline": self._render_attack_chain_mermaid(refined_iocs),
                
                "key_indicators": self._prepare_key_indicators(refined_iocs),
                "phishing_lnks": self._prepare_origin_seeds(analyzer.pivot_seeds, "PHISHING", origin_stories),
                "drop_items": self._prepare_origin_seeds(analyzer.pivot_seeds, "DROP", origin_stories, exclude="PHISHING"),
                "anti_forensics_tools": self._prepare_anti_forensics(refined_iocs, dfs_for_ioc),
                "technical_findings": tech_findings,
                "high_interest_lnks": high_lnks,
                "generic_lnks": gen_lnks,
                "attack_chain_mermaid": "",  # [FIX] Removed duplicate - mermaid_timeline already shows in Executive Summary
                "plutos_section": self._render_plutos_section_text(dfs_for_ioc, analyzer),
                "stats": self._prepare_stats(analyzer, analysis_data, dfs_for_ioc, refined_iocs),
                "recommendations": self._prepare_recommendations(analyzer),
                "all_iocs": refined_iocs,
                
                # ═══════════════════════════════════════════════════════════════
                # [Feature 5] Noise Zero Implementation + Display Beautification
                # Split IOCs into Section 7.1 (Top 15 Critical) and 7.2 (Contextual + Overflow)
                # ═══════════════════════════════════════════════════════════════
                "iocs_section_7_1": self._clean_display_data(self._split_iocs_top15(refined_iocs)[0]),
                "iocs_section_7_2": self._clean_display_data(self._split_iocs_top15(refined_iocs)[1][:50])  # Limit to 50
            }
            with open(log_file, "a", encoding="utf-8") as log: 
                log.write(f"[{datetime.now()}] Context Prepared. Keys: {list(context.keys())}\n")
                if 'dynamic_verdict' in context:
                    log.write(f"[{datetime.now()}] Verdict Type: {type(context['dynamic_verdict'])}\n")
        except Exception as e:
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"[{datetime.now()}] Context Preparation Failed: {e}\n")
                import traceback
                traceback.print_exc(file=log)
            raise e

        # 2. Render Template
        try:
            template = self.template_env.get_template("report.md.j2")
            rendered_md = template.render(context)
            
            # 3. Write Output
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(rendered_md)
            
            msg = f"    [+] Report Generated: {out_file}"
            print(msg)
            with open(log_file, "a", encoding="utf-8") as log: log.write(f"[{datetime.now()}] {msg}\n")
            
        except Exception as e:
            msg = f"    [!] Jinja2 Rendering Failed: {e}"
            print(msg)
            import traceback
            traceback.print_exc()
            
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"[{datetime.now()}] {msg}\n")
                traceback.print_exc(file=log)
        
        # 4. Generate per-user activity reports
        try:
            events_source = context.get('all_iocs', analyzer.visual_iocs if analyzer else [])
            user_reporter = UserActivityReporter(self.hostname)
            user_reporter.generate(events_source, self.output_path)
        except Exception as e:
            print(f"    [!] UserReporter warning: {e}")
            import traceback
            traceback.print_exc()

    def _group_all_iocs(self, iocs, analyzer=None):
        refined_iocs = [] # [Hybrid Fix] Dynamic Noise Filter Integration
        # [Refactor v2.0] GARBAGE_PATTERNS now loaded from YAML via intel_module
        # [Refactor] Load patterns from Intel module
        from tools.lachesis.intel import IntelManager

        # Flattened grouping for Section 7
        grouped_iocs = []
        
        # ═══════════════════════════════════════════════════════════
        # [Fix] Ultra-Hard Noise Filter (WinSxS / Store Apps / Updates)
        # ═══════════════════════════════════════════════════════════
        # Get patterns from Intel (Not Hardcoded here)
        HARD_NOISE_PATTERNS = IntelManager.get_renderer_noise_patterns()
        RESCUE_TAGS = IntelManager.get_rescue_tags()
        
        # ═══════════════════════════════════════════════════════════
        # [Phase 5+] Hybrid Smart Filter (The Safety Valve Edition)
        # Priority: Remove noise UNLESS score >= 500 (Critical)
        # Use centralized logic from analyzer._is_noise
        # AND Redundant Check for safety
        # ═══════════════════════════════════════════════════════════
        
        
        filtered_iocs = []
        # Logging removed for production cleanliness, but structure kept for logic clarity
        
        # [DEBUG PROBE]
        try:
            with open("renderer_probe.log", "w") as f:
                 f.write(f"PROBE START. Analyzer type: {type(analyzer)}\n")
                 f.write(f"Has _is_noise? {hasattr(analyzer, '_is_noise')}\n")
        except: pass

        for ev in iocs:
            # [Grimoire v6.3/v6.4] Image Hygiene + Evidence Shield
            v = str(ev.get('Value', '')).lower()
            p = str(ev.get('Path', '')).lower()
            t = str(ev.get('Target_Path', '')).lower()
            c = str(ev.get('CommandLine', '')).lower()
            check_val = f"{v} | {p} | {t} | {c}"
            norm_check = check_val.replace("/", "\\").replace(".\\", "").replace("\\\\", "\\")
            tags = str(ev.get('Tag', '')).upper()
            score = int(ev.get('Score', 0))
            fname = v.split("\\")[-1].split("/")[-1]
            
            # ═══════════════════════════════════════════════════════════
            # [Fix] Hard Noise Filter Check
            # ═══════════════════════════════════════════════════════════
            
            # EXTREME NOISE: Always filter, even if rescued (component hashes, UWP apps, etc.)
            EXTREME_NOISE = [
                "_none_", "_10.0.", "_amd64_", "_x86_",  # WinSxS component hashes
                "~31bf3856ad364e35~",  # Microsoft SxS catalog hash signature
                "windows\\winsxs", 
                "windowsapps\\",      # UWP Store Apps
                "infusedapps\\",      # Pre-installed UWP
                "8wekyb3d8bbwe",      # Microsoft Store app SID pattern
                "deletedalluserpackages",
                "nativeimages_",      # .NET Native Images (GAC cache)
                "\\assembly\\gac",    # .NET GAC assemblies
                "microsoft.windows.cortana",  # Cortana UWP
                "msfeedssync",
                "mobsync",
                "tzsync",
                "appmodel-runtime",           # AppX Runtime logs
                "contentdeliverymanager",     # Windows CDM
                "devicesearchcache",          # Cortana search cache
                # XAMPP Legitimate Components (non-threat library files)
                "xampp\\php\\pear",
                "xampp\\apache\\manual",
                "xampp\\tomcat\\webapps\\docs",
                "xampp\\tomcat\\webapps\\examples",
                "xampp\\src\\",
                "xampp\\licenses",
                "xampp\\locale",
                "xampp\\php\\docs",
                "xampp\\cgi-bin",
                "\\pear\\docs",
                "\\pear\\tests",
                # XAMPP Extended Noise (Perl/PHP/Apache/MySQL)
                "xampp\\perl\\lib",
                "xampp\\perl\\vendor",
                "filezillaftp\\source",
                "apache\\icons",
                "mercurymail\\",
                "mysql\\data\\",
                "phpmyadmin\\js\\",
                "phpmyadmin\\libraries\\",
                "phpmyadmin\\themes\\",
                "webalizer\\",
                "sendmail\\",
                # XAMPP Additional Noise (Tomcat, Static, Sessions)
                "xampp\\tmp\\sess_",
                "tomcat\\webapps\\manager",
                "tomcat\\webapps\\host-manager",
                "tomcat\\webapps\\root",
                "phpmyadmin\\doc\\",
                "htdocs\\img\\",
                "security\\htdocs\\",
                # XAMPP Dashboard & Docs (Web Resources)
                "htdocs\\dashboard\\",
                "htdocs\\docs\\",
                "dashboard\\images\\",
                "dashboard\\css\\",
                "dashboard\\docs\\",
                # XAMPP Libraries & Extras
                "php\\extras\\",
                "php\\tests\\",
                "perl\\bin\\",
                "perl\\site\\",
                # XAMPP Apache/MySQL Config & Locales
                "apache\\include\\",
                "apache\\modules\\",
                "mysql\\share\\",
                "phpmyadmin\\locale\\",
                # XAMPP Test & Misc
                "webdav\\",
                "\\flags\\",
                "\\install\\",
                "phpids\\tests\\",
                # Browser Cache & DVWA Static Resources
                "content.ie5\\",
                "dvwa\\dvwa\\images\\",
                "dvwa\\dvwa\\css\\",
                "dvwa\\external\\",
                # XAMPP System Libraries (Loader noise)
                "apache\\bin\\iconv\\",
                "php\\ext\\",
                "tomcat\\lib\\",
                # MySQL Metadata (Running service artifacts)
                ".frm",
                ".myd",
                ".myi",
                "performance_schema\\",
                # XAMPP Icons & Static Assets
                "xampp\\img\\",
                "hackable\\users\\",
                "favicon.ico",
                # AGGRESSIVE NOISE FILTERS (95%+ FP in INTERNAL_RECON)
                "xampp\\apache\\bin\\",
                "xampp\\mysql\\bin\\",
                "xampp\\php\\",
                "xampp\\tomcat\\bin\\",
                # Library/Binary extensions (service loading)
                ".dll",
                ".jar",
                ".so",
                # Help & Documentation noise
                ".chm",
                ".hlp",
                "readme.txt",
                "license.txt",
                "install.txt",
                "changes.txt",
                # MySQL system tables
                "information_schema\\",
                "mysql\\mysql\\",
                # Tomcat/Java artifacts
                "catalina\\",
                ".class",
            ]
            if any(xp in norm_check for xp in EXTREME_NOISE):
                continue  # Unconditionally drop system noise
            
            is_rescued = any(rt in tags for rt in RESCUE_TAGS)
            
            if not is_rescued:
                # Hard Filter Check
                if any(np in norm_check for np in HARD_NOISE_PATTERNS):
                    continue  # Drop noisy artifact
                
                # AppData Packages check (common noise source)
                if "appdata\\local\\packages" in norm_check and score < 500:
                    continue
            
            # [v6.4] Evidence Shield - Recon keywords protect images
            RECON_KEYWORDS = ["xampp", "phpmyadmin", "admin", "dashboard", "kibana", 
                              "phishing", "c2", "login", "webshell", "backdoor", "exploit"]
            image_exts = [".png", ".jpg", ".gif", ".ico", ".bmp"]
            if any(fname.endswith(ext) for ext in image_exts):
                if any(kw in norm_check for kw in RECON_KEYWORDS):
                    ev['Score'] = max(score, 600)
                    if "INTERNAL_RECON" not in tags:
                        ev['Tag'] = (tags + ",INTERNAL_RECON").strip(',')
                    filtered_iocs.append(ev)
                    continue  # Protected - keep and skip noise checks
            
            # [v6.3] Image Hygiene - Extended system/cache paths
            noise_exts = [".mui", ".nls", ".dll", ".sys", ".jpg", ".png", ".gif", ".ico", ".xml", ".dat"]
            system_resource_paths = [
                "windows\\system32", "windows\\syswow64", "windows\\web\\",
                "windows\\branding\\", "program files\\windowsapps",
                "programdata\\microsoft\\windows\\systemdata",
            ]
            browser_cache_paths = [
                "appdata\\local\\microsoft\\windows\\inetcache",
                "appdata\\local\\google\\chrome\\user data\\default\\cache",
                "temporary internet files", "content.ie5",
            ]
            
            if any(fname.endswith(ext) for ext in noise_exts):
                # Critical tags protect
                if any(t in tags for t in ["RECON", "EXFIL", "MASQUERADE", "SCREENSHOT", "LATERAL"]):
                    pass  # Keep
                elif any(sp in norm_check for sp in system_resource_paths):
                    continue  # Drop
                elif any(bp in norm_check for bp in browser_cache_paths):
                    continue  # Drop
            
            # 1. Trusted Analyzer Logic (Must be robust)
            if analyzer and hasattr(analyzer, '_is_noise'):
                if analyzer._is_noise(ev):
                    continue
            
            # 2. Redundant Check (Using Shared Pattern List from YAML) - Belt & Suspenders
            is_noise = False
            if score < 500 and not any(x in tags for x in ["LATERAL", "RANSOM", "WIPER"]):
                garbage_patterns = IntelManager.get_garbage_patterns()
                for g in garbage_patterns:
                    if g in norm_check:
                         is_noise = True
                         break
            
            if is_noise:
                 continue

            filtered_iocs.append(ev)
        
        # Use filtered list for grouping
        iocs = filtered_iocs
        
        # Helper: Extract directory path
        def get_parent(path):
            if not path: return ""
            return str(Path(path).parent)

        # 1. Bucket by Type + Tag + ParentDir
        buckets = {}
        processed_ids = set() # To avoid double processing if logic changes

        # Sort by directory to help sequential processing
        try:
            sorted_iocs = sorted(iocs, key=lambda x: get_parent(x.get('Value', '')))
        except:
            sorted_iocs = iocs
        
        # Grouping candidates
        for ev in sorted_iocs:
            cat = self._get_event_category(ev)
            tag = str(ev.get('Tag', ''))
            val = str(ev.get('Value', ''))
            score = int(ev.get('Score', 0))
            
            # [DEBUG] Trace 7za
            if "7za" in val.lower():
                print(f"[DEBUG-7ZA-GROUP] Val={val} Score={score} Tag={tag} Cat={cat}")
            
            # Smart Filename Extraction for Grouping
            filename = str(ev.get('FileName') or ev.get('Target_FileName') or ev.get('Target_Path') or '')
            if not filename and "USN" in tag:
                # Try parsing from Note or Summary if it looks like a path
                # Note format: "Lateral Movement (USN)" or similar
                # Summary might be better.
                summ = str(ev.get('Summary', ''))
                if "." in summ and "\\" in summ: # rudimentary path check
                     filename = summ
                elif str(ev.get('Note', '')).find(":\\") > 0:
                     filename = str(ev.get('Note', ''))

            # --- PHASE 0: Score Adjustment (Context-Aware) ---
            # Apply penalty/boost BEFORE filtering to ensure WindowsApps gets reduced
            path_for_adjust = str(ev.get('Value', '') or ev.get('Path', ''))
            original_score = score
            if analyzer:
                score, new_tags = analyzer.adjust_score(path_for_adjust, score)
            else:
                new_tags = []
            
            # [Grimoire v6.1] Sensitive & Recon Keyword Boost (Aggressive)
            # Check Full Path for critical keywords that might be missed by simple filename checks
            normalized_val = path_for_adjust.lower().replace("\\", "/")
            critical_keywords = [
                "password", "secret", "confidential", "credentials", "login", 
                "shadow", "kimitachi", "topsecret", "機密", "社外秘"
            ]
            if any(k in normalized_val for k in critical_keywords):
                score = 800
                new_tags.append("SENSITIVE_DATA_ACCESS")
                
            # [Grimoire v6.1] Context Injection for 'readme.txt'
            # If readme.txt is found in a suspicious folder (e.g. SetMACE), annotate it
            if "readme.txt" in normalized_val and "setmace" in normalized_val:
                ev['Note'] = f"{ev.get('Note', '')} (Associated with SetMACE)"

            ev['Score'] = score  # Update the event's score permanently
            if new_tags:
                existing_tags = tag.split(",") if tag else []
                ev['Tag'] = ",".join(list(set(existing_tags + new_tags)))
                tag = ev['Tag'] # Update local var for filtering
            
            rescue_tags = ["CRITICAL", "TIMESTOMP", "KNOWN_WEBSHELL", "C2", "RANSOM", "ROOTKIT"]
            has_rescue_tag = any(t in tag for t in rescue_tags)
            
            # [DEBUG] Trace SetMACE/PuTTY in Renderer
            if "TIMESTOMP" in tag or "REMOTE_ACCESS" in tag or score >= 300:
                  with open("renderer_trace.log", "a", encoding="utf-8") as f:
                       f.write(f"[RENDERER] Validating: {filename} Sc={score} Tag={tag} Rescue={has_rescue_tag}\n")
            
            # [Debug Verbose]
            if "USN" in tag:
                with open("debug_verbose.log", "a", encoding="utf-8") as f:
                     import os
                     if os.path.getsize("debug_verbose.log") < 50000: # Increase limit
                         f.write(f"USN Item: Cat={cat} Tag={tag} Val={val} Sc={score} Time={ev.get('Time')}\n")
            
            # [Phase 6] Category-based Thresholding (Grimoire Engine v6.0)
            # High-Confidence Filtering: Only show Score >= 300 unless critical context
            CATEGORY_THRESHOLDS = {
                "EXECUTION": 300,        # [Strict] Filter reconnaissance and noise (was 150)
                "VULNERABLE APP": 300,   # [Strict] High noise potential (was 150)
                "ANTI-FORENSICS": 300,   # [Strict] Now relying on boosted scores for real findings (was 50)
                "LATERAL MOVEMENT": 300, # [Strict] (was 50)
                "TIMESTOMP": 300,        # [Strict] (was 50)
                "DEFAULT": 300           # Base threshold (was 50)
            }
            
            threshold = CATEGORY_THRESHOLDS.get(cat, CATEGORY_THRESHOLDS["DEFAULT"])
            if "VULNERABLE" in cat: threshold = CATEGORY_THRESHOLDS["VULNERABLE APP"] # Match partial keys

            # Rescue Tags: Keep these even if score is low (Contextual Importance)
            # [Grimoire v6.1] Force Merge: Added LATERAL, RECON, SENSITIVE, EXFIL to rescue list
            rescue_tags = [
                "CRITICAL", "KNOWN_WEBSHELL", "C2", "RANSOM", "ROOTKIT", "MANUAL_REVIEW",
                "LATERAL", "UNC_", "INTERNAL_RECON", "SENSITIVE", "EXFIL", "DATA_EXFIL" 
            ]
            has_rescue_tag = any(t.upper() in tag.upper() for t in rescue_tags)
            
            # Strict Drop for low scores (using Category Thresholds)
            if score < threshold and not has_rescue_tag:
                 continue

            # --- PHASE 1: Grouping Logic ---
            
            should_group = False
            group_key = ""
            
            # [Grimoire v6.2] Toolkit Grouping (Parent-Child)
            # If a directory contains a high-score tool (>= 700), group all files in that directory
            parent_dir = get_parent(val).lower()
            well_known_tool_dirs = ["setmace", "mimikatz", "sdelete", "psexec", "lazagne", "wce"]
            is_tooldir = any(t in parent_dir for t in well_known_tool_dirs)
            
            if is_tooldir:
                should_group = True
                # Extract tool name from path
                tool_name = "Unknown Toolkit"
                for t in well_known_tool_dirs:
                    if t in parent_dir: tool_name = t.upper(); break
                group_key = f"TOOLKIT|{tool_name}"
            
            # 1.1 VULNERABLE APP (Bulk Grouping)
            elif "VULNERABLE APP" in cat:
                should_group = True
                group_key = f"VULN|{tag}" 

            # [Feature] Filename Prefix Grouping (choco, sdelete)
            # Groups choco.exe, choco.exe.manifest, choco.exe.pf -> choco.exe
            elif any(prefix in filename.lower() for prefix in ["choco", "sdelete", "bcwipe"]):
                should_group = True
                # Extract prefix
                prefix = next(p for p in ["choco", "sdelete", "bcwipe"] if p in filename.lower())
                group_key = f"TOOL_PREFIX|{prefix}"
                filename = f"{prefix} (Aggregated Artifacts)" # For display 

            # 1.2 RECON / EXFILTRATION (Google Search Grouping)
            # [User Request] Group repetitive Google URLs to improve readability
            elif "RECON" in tag or "EXFIL" in tag:
                # Check for Google Search URL patterns
                if "google" in val.lower() and ("search?" in val or "url?" in val):
                    should_group = True
                    group_key = "RECON_GOOGLE_SEARCH"
                    filename = "Google Search URLs (Reconnaissance)" # Override filename for display

            # 1.2 WEBSHELL (Obfuscation Grouping) - Now mostly handled by Score Cut (<90 dropped)
            elif "WEBSHELL" in cat:
                if score <= 85 and "OBFUSCATION" in tag and not has_rescue_tag:
                    parent = get_parent(val)
                    group_key = f"OBFUSC|{parent}"
                    should_group = True

            # 1.3 LATERAL / USN Condensation
            # Group by Filename for USN bursts
            elif "LATERAL" in cat:
                 # Check if USN related (Value is Action like 'FileCreate') OR Tag has USN
                 if ("USN" in tag or "|" in val):
                      if filename:
                          group_key = f"USN|{filename}"
                          should_group = True
                      else:
                          # Fallback: Group by Timestamp (Minute precision to catch bursts)
                          # Time format often: 2015-09-03 10:03:01
                          t = str(ev.get('Time', ''))
                          if len(t) >= 16:
                              group_key = f"USN|BURST|{t[:16]}" # Group by minute e.g. 2015-09-03 10:03
                              should_group = True
                          
                          # [Debug]
                          if "USN" in tag:
                               with open("debug_grouping.log", "a", encoding="utf-8") as f:
                                   f.write(f"USN Item: T={t} F={filename} Group={should_group} Key={group_key}\n")

            if not should_group:
                grouped_iocs.append(ev)
                continue
            
            if group_key not in buckets: buckets[group_key] = []
            buckets[group_key].append(ev)
            
        # 2. Process Buckets
        with open("debug_grouping.log", "a", encoding="utf-8") as f:
             f.write(f"Buckets: {len(buckets)} keys. Sizes: {[len(v) for v in buckets.values()]}\n")

        for key, bucket in buckets.items():
            # Threshold: 5 items (User suggested 10 for USN, but 5 is safe default)
            threshold = 5 
            if "USN" in key: threshold = 5 # Strict condensation for USN
            
            if len(bucket) >= threshold:
                first = bucket[0]
                
                # Determine Label
                if "VULN" in key:
                    label_type = "VULNERABLE APP"
                    label_desc = f"Files (Related to {first.get('Tag', '')})"
                    
                elif "RECON_GOOGLE_SEARCH" in key:
                    label_type = "RECONNAISSANCE"
                    label_desc = "Google Search URLs related to Exfiltration/Recon"
                    
                elif "OBFUSC" in key:
                    label_type = "WEBSHELL" 
                    filenames = [os.path.basename(str(b.get('Value'))) for b in bucket[:3]]
                    examples = ", ".join(filenames)
                    label_desc = f"Files (Potential Noise / Obfuscated Libs) - e.g. {examples}..."
                    
                elif "TOOL_PREFIX" in key:
                    prefix_name = key.split("|")[1].upper()
                    label_type = "EXECUTION" # or STAGING_TOOL
                    # Inherit type from first event if possible
                    if "STAGING" in str(first.get('Tag', '')): label_type = "STAGING TOOL"
                    elif "ANTI" in str(first.get('Tag', '')): label_type = "ANTI-FORENSICS"
                    label_desc = f"{prefix_name} Related Artifacts (Exe, Prefetch, Logs etc.)"
                    
                elif "USN" in key:
                    label_type = "LATERAL MOVEMENT"
                    # User: 10x USN Events (FileCreate/DataExtend) - tmpudvfh.php
                    # Using Set of Actions for description
                    actions = sorted(list(set(str(b.get('Value')) for b in bucket)))
                    action_str = "/".join(actions[:3]) # Limit to 3 actions
                    if len(actions) > 3: action_str += "..."
                    
                    if "BURST" in key:
                        label_desc = f"USN Activity Burst ({action_str}) - Unknown File"
                    else:
                        fname = key.split("|")[1]
                        # Clean filename if it's a full path
                        fname_short = os.path.basename(fname)
                        label_desc = f"USN Events ({action_str}) - File: {fname_short}"

                else:
                    label_type = "GROUP"
                    label_desc = "Events"
                
                # Check timestamps span
                times = [b.get('Time') for b in bucket if b.get('Time')]
                t_str = "Unknown"
                if times: 
                    min_t, max_t = min(times), max(times)
                    t_str = f"{min_t} - {max_t}"
                    # If simplified to minutes or same second
                    if min_t == max_t: t_str = str(min_t)
                
                summary_ev = first.copy()
                summary_ev['Type'] = label_type 
                summary_ev['Value'] = f"{len(bucket)}x {label_desc}" # This value will be shown in table
                summary_ev['Note'] = "Grouped Artifacts"
                summary_ev['Time'] = t_str
                # Inherit Max Score of group to avoid hiding risk
                max_score = max(int(b.get('Score', 0)) for b in bucket)
                summary_ev['Score'] = max_score
                
                grouped_iocs.append(summary_ev)
            else:
                grouped_iocs.extend(bucket)
        
        return sorted(grouped_iocs, key=lambda x: str(x.get('Score', 0)), reverse=True)

    def _split_iocs_top15(self, refined_iocs):
        """
        [Feature 5] Noise Zero: Split IOCs into Top 15 Critical and Overflow/Contextual.
        
        Returns:
            tuple: (section_7_1, section_7_2)
                - section_7_1: Top 15 IOCs with Score >= 500
                - section_7_2: Overflow (16+) + Contextual (300-499), sorted by score
        """
        # ═══════════════════════════════════════════════════════════════
        # [Fix] Ensure Sorting BEFORE Slicing - Critical Bug Fix!
        # ═══════════════════════════════════════════════════════════════
        
        # まず全体をスコア降順でソート（超重要！）
        refined_iocs.sort(key=lambda x: int(x.get('Score', 0)), reverse=True)

        # 1. Extract candidates (Score >= 500 and 300-499)
        high_conf_candidates = [i for i in refined_iocs if int(i.get('Score', 0)) >= 500]
        context_candidates = [i for i in refined_iocs if 300 <= int(i.get('Score', 0)) < 500]
        
        # 2. Top 15 slicing (now guaranteed to be highest scores first)
        section_7_1 = high_conf_candidates[:15]
        overflow_high = high_conf_candidates[15:]  # 16th onwards
        
        # 3. Merge overflow with contextual and re-sort
        # This ensures Score 1000 at position 16 appears at top of Section 7.2
        section_7_2 = overflow_high + context_candidates
        section_7_2.sort(key=lambda x: int(x.get('Score', 0)), reverse=True)
        
        return (section_7_1, section_7_2)

    # --- Context Helper Methods ---

    def _get_attack_methods(self, analyzer):
        t = self.txt
        visual_iocs = analyzer.visual_iocs
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_anti = any("ANTI" in str(ioc.get('Type', '')) or "ANTIFORENSICS" in str(ioc.get('Tag', '')) for ioc in visual_iocs)
        has_lateral = any("LATERAL" in str(ioc.get('Type', '')) or "LATERAL" in str(ioc.get('Tag', '')) or "UNC_EXECUTION" in str(ioc.get('Tag', '')) for ioc in visual_iocs)
        has_recon = any("RECON" in str(ioc.get('Type', '')) or "INTERNAL_RECON" in str(ioc.get('Tag', '')) for ioc in visual_iocs)

        methods = []
        if has_phishing: methods.append(t.get('attack_phishing', "Phishing"))
        if has_masquerade: methods.append(t.get('attack_masquerade', "Masquerading"))
        if has_timestomp: methods.append(t.get('attack_timestomp', "Timestomping"))
        if has_paradox: methods.append(t.get('attack_paradox', "Time Paradox"))
        if has_anti: methods.append(t.get('attack_anti', "Anti-Forensics"))
        if has_lateral: methods.append(t.get('attack_lateral', "Lateral Movement"))
        if has_recon: methods.append(t.get('attack_recon', "Internal Reconnaissance"))
        if not methods: methods.append(t.get('attack_default', "General Intrusion"))
        return methods

    def _get_display_value(self, row):
        """
        Smart Formatting: Prioritize meaningful columns over generic 'system' or placeholders.
        """
        candidates = [
            row.get("FileName"),
            row.get("Target_Path"),
            row.get("Target_FileName"), 
            row.get("CommandLine"),
            row.get("ParentPath"),   # [Fix] Fallback for USN/MFT where FileName is hash
            row.get("Reg_Key"),
            row.get("Service_Name"), # [v5.7.1] Smart Formatting: Service
            row.get("Payload"),
            row.get("Message"),      # [v5.7.1] Smart Formatting: EventMsg
            row.get("Action"),
            row.get("Value")         # [Fix] Fallback to Value (e.g. URL)
        ]
        fallback_hash = None
        for c in candidates:
            val = str(c).strip()
            if not c or val in ["", "None", "N/A"]: continue
            
            # Check if likely hash (32=MD5, 40=SHA1, 64=SHA256) and hex-only
            if len(val) in [32, 40, 64] and re.match(r"^[a-fA-F0-9]+$", val):
                if not fallback_hash: fallback_hash = val
                continue # Skip hash, look for better name
                
            return val # Found meaningful name
            
        return fallback_hash if fallback_hash else "Unknown Activity"

    def _compress_timeline_for_mermaid(self, events, time_window_minutes=5):
        """
        Timeline Aggregation: Group dense events into buckets to declutter visualization.
        """
        compressed = []
        if not events: return []
        
        # Sort by time just in case
        sorted_events = sorted(events, key=lambda x: x.get('Time', ''))
        
        # Parse first event time
        try:
            current_bucket = sorted_events[0].copy()
            current_bucket['dt'] = datetime.strptime(str(current_bucket['Time']).split('.')[0], '%Y-%m-%dT%H:%M:%S')
        except:
            return events # Fallback if parsing fails

        count = 1
        bucket_tags = set()
        if 'Tag' in current_bucket: bucket_tags.update(str(current_bucket['Tag']).split(','))

        for i in range(1, len(sorted_events)):
            ev = sorted_events[i].copy()
            try:
                ev_dt = datetime.strptime(str(ev['Time']).split('.')[0], '%Y-%m-%dT%H:%M:%S')
            except:
                continue

            delta = ev_dt - current_bucket['dt']
            if delta.total_seconds() < (time_window_minutes * 60):
                # Merge into bucket
                count += 1
                if 'Tag' in ev: bucket_tags.update(str(ev['Tag']).split(','))
            else:
                # Flush bucket
                current_bucket['Display'] = f"{', '.join(sorted(bucket_tags))} ({count} Events)" if count > 1 else current_bucket.get('Summary', '')
                current_bucket['Tag'] = ', '.join(sorted(bucket_tags))
                compressed.append(current_bucket)
                
                # Start new bucket
                current_bucket = ev
                current_bucket['dt'] = ev_dt
                count = 1
                bucket_tags = set()
                if 'Tag' in current_bucket: bucket_tags.update(str(current_bucket['Tag']).split(','))
        
        # Flush last bucket
        current_bucket['Display'] = f"{', '.join(sorted(bucket_tags))} ({count} Events)" if count > 1 else current_bucket.get('Summary', '')
        current_bucket['Tag'] = ', '.join(sorted(bucket_tags))
        compressed.append(current_bucket)
        
        return compressed

    def _prepare_key_indicators(self, events):
        grouped = {}
        cat_titles = {
            "INITIAL ACCESS": "🎣 Initial Access", "ANTI-FORENSICS": "🙈 Anti-Forensics",
            "SYSTEM MANIPULATION": "🚨 System Time Manipulation", "PERSISTENCE": "⚓ Persistence",
            "EXECUTION": "⚡ Execution", "TIMESTOMP (FILE)": "🕒 Timestomp (Files)",
            "WEBSHELL": "🕸️ WebShell Intrusion", "LATERAL MOVEMENT": "🐛 Lateral Movement",
            "VULNERABLE APP": "🔓 Vulnerable Application",
            "REMOTE_ACCESS": "📡 Remote Access"
        }
        
        temp_groups = {}
        for ev in events:
            # [v7.0 User Request] Raised threshold from 50 to 500 to filter diagnostic noise
            if ev.get('Score', 0) < 500 and "CRITICAL" not in str(ev.get('Type', '')): continue
            cat = self._get_event_category(ev)
            if cat not in temp_groups: temp_groups[cat] = []
            
            impact = "-"
            extra = ev.get('Extra', {})
            tag = str(ev.get('Tag', ''))
            
            # [Grimoire v6.2] CommandLine Argument Extraction
            # Check for CommandLine in various locations
            cmd_line = ev.get('CommandLine') or ev.get('Payload') or extra.get('CommandLine', '')
            if cmd_line and len(str(cmd_line)) > 3:
                impact = f"`{str(cmd_line)[:50]}...`" if len(str(cmd_line)) > 50 else f"`{cmd_line}`"
            elif "SYSTEM_TIME" in tag or "4616" in tag or "TIME_PARADOX" in str(ev.get('Type', '')):
                impact = "**System Clock Altered**"
            elif cat == "INITIAL ACCESS":
                tgt = extra.get('Target_Path', 'Unknown')
                if tgt and tgt != "Unknown":
                    impact = f"Target: {tgt[:30]}..."
            ev['Impact'] = impact
            # [Refinement] Smart Formatting
            ev['Value'] = self._get_display_value(ev)
            temp_groups[cat].append(ev)

        # [Grouping] Collapse repetitive events
        for k in temp_groups:
            if k == "VULNERABLE APP" or k == "EXECUTION":
                bucket = []
                collapsed_group = []
                
                # Simple groupings by Tag
                tag_map = {}
                for ev in temp_groups[k]:
                    t = ev.get('Tag', 'Other')
                    if t not in tag_map: tag_map[t] = []
                    tag_map[t].append(ev)
                
                for t, ev_list in tag_map.items():
                    if len(ev_list) > 5:
                        first = ev_list[0]
                        last = ev_list[-1]
                        summary_ev = first.copy()
                        summary_ev['Value'] = f"{len(ev_list)}x Files ({t})"
                        summary_ev['Impact'] = f"Bulk Artifacts (e.g. {first.get('Value')})"
                        summary_ev['Time'] = f"{first.get('Time')} - {last.get('Time')}"
                        collapsed_group.append(summary_ev)
                    else:
                        collapsed_group.extend(ev_list)
                temp_groups[k] = collapsed_group

            temp_groups[k].sort(key=lambda x: x.get('Time', '9999'))

        ordered_keys = sorted(temp_groups.keys(), key=lambda k: 0 if "SYSTEM" in k else 1)
        final_groups = {cat_titles.get(k, k): temp_groups[k] for k in ordered_keys}
        return final_groups

    def _prepare_origin_seeds(self, seeds, include_keyword, origin_stories, exclude=None):
        results = []
        seen_targets = set()
        for seed in seeds:
            reason = seed.get("Reason", "")
            target = seed.get('Target_File', '')
            
            if include_keyword in reason and (not exclude or exclude not in reason):
                # [Fix] LNK Noise Filter (Initial Access Table)
                t_lower = target.lower()
                is_std_app = any(p in t_lower for p in ["system32", "program files", "control panel", "windows power"])
                is_known_lnk = any(k in t_lower for k in ["command prompt", "file explorer", "task manager", "run.lnk"])
                if is_std_app or is_known_lnk: continue

                if target in seen_targets: continue
                seen_targets.add(target)
                
                name = target
                origin_desc = "❓ No Trace Found (Low Confidence)"
                story = next((s for s in origin_stories if s["Target"] == name), None)
                if story:
                    ev = story["Evidence"][0]
                    url = ev.get("URL", "")
                    url_display = (url[:50] + "...") if len(url) > 50 else url
                    gap = ev.get('Time_Gap', '-')
                    conf = story.get("Confidence", "LOW")
                    reason_story = story.get("Reason", "")
                    icon = "✅" if conf == "HIGH" else "⚠️" if conf == "MEDIUM" else "❓"
                    prefix = "**Confirmed**" if conf == "HIGH" else "Inferred" if conf == "MEDIUM" else "Weak"
                    origin_desc = f"{icon} **{prefix}**: {reason_story}<br/>🔗 `{url_display}`<br/>*(Gap: {gap})*"
                
                seed['Origin_Desc'] = origin_desc
                results.append(seed)
        return results

    def _prepare_anti_forensics(self, ioc_list, dfs):
        t = self.txt
        af_tools = [ioc for ioc in ioc_list if "ANTI" in str(ioc.get("Type", "")) or "WIPE" in str(ioc.get("Type", ""))]
        processed = []
        seen = set()
        
        for tool in af_tools:
            name = tool.get("Value", "Unknown").upper()
            if name in seen: continue
            seen.add(name)
            
            run_count = self._extract_dual_run_count(tool, dfs)
            desc = t.get('note_anti_cleanup', "Cleanup tool.")
            if "BCWIPE" in name: desc = t.get('note_anti_bcwipe', "Military wiper.")
            elif "CCLEANER" in name: desc = t.get('note_anti_ccleaner', "System cleaner.")
            
            note = t.get('note_anti_cleanup', "")
            
            processed.append({
                "Name": name,
                "RunCount": run_count,
                "LastRun": tool.get("Time", "Unknown").replace("T", " ")[:19],
                "Desc": desc,
                "AnalystNote": note
            })
        return processed

    def _prepare_technical_findings_from_list(self, ioc_list, analyzer, origin_stories):
        # [Fix] Apply global threshold (500) to Detailed Findings too.
        # Ensure ADS/Masquerade items are included ONLY if they meet score or are force-included
        high_conf_events = [ioc for ioc in ioc_list if (int(ioc.get('Score', 0) or 0) >= 500) or analyzer.is_force_include_ioc(ioc)]
        groups = {}
        
        for ioc in high_conf_events:
            cat = self._get_event_category(ioc)
            if "ANTI" in cat: continue
            if cat not in groups: groups[cat] = []
            
            insight = analyzer.generate_ioc_insight(ioc)
            val = ioc.get('Value', '')
            story = next((s for s in origin_stories if s["Target"] == val), None) if origin_stories else None
            if story and story.get("Confidence") == "HIGH":
                 gap = story['Evidence'][0].get('Time_Gap', '-')
                 web_note = self.txt.get('web_download_confirmed', "Web Download").format(gap=gap)
                 insight = web_note + (insight if insight else "")
            
            # [New] Narrator Logic: Generate rich description text
            narrative = self._generate_tech_narrative(ioc, ioc_list)
            if narrative:
                # Append to existing insight or replace
                insight = (insight + "\n\n" + narrative) if insight else narrative
            
            ioc['Insight'] = insight
            groups[cat].append(ioc)
        
        # [User Request] Apply USN Storm Condenser for LATERAL MOVEMENT
        with open("debug_groups.log", "a", encoding="utf-8") as f:
             import datetime
             f.write(f"\n--- Call at {datetime.datetime.now()} ---\n")
             f.write(f"Input List Size: {len(ioc_list)}\n")
             f.write(f"Groups Keys: {list(groups.keys())}\n")
             for k, v in groups.items():
                 f.write(f"Key: '{k}' Count: {len(v)}\n")

        if "LATERAL MOVEMENT" in groups:
             groups["LATERAL MOVEMENT"] = self._condense_usn_events(groups["LATERAL MOVEMENT"])
             
        return groups



    def _condense_usn_events(self, events):
        """
        USN Journal high-volume condenser. Groups by (TimeSecond, FileName).
        Target: Source/Tag is USN, Category LATERAL or FILE.
        Handles both Visual IOCs and Timeline Events.
        """
        condensed = []
        buffer = {} # Key: (TimeSecond, FileName), Value: EventDict
        
        for ev in events:
            # Check fields
            tag = str(ev.get('Tag', ''))
            src = str(ev.get('Source', ''))
            cat = str(ev.get('Category', '') or ev.get('Type', '')).upper()
            
            is_usn_source = "USN" in tag or "USN" in src
            # [User Request] Modified to accept FILE category (due to demotion)
            is_target_cat = "LATERAL" in cat or "FILE" in cat
            
            if not (is_usn_source and is_target_cat):
                condensed.append(ev)
                continue

            # Grouping Key: Time (Second) ONLY to achieve max decluttering
            # User request: "Group single lines if same second"
            t_str = str(ev.get('Time', ''))
            ts_sec = t_str[:19] # "2015-09-03 10:03:01"
            
            # Filename extraction
            fname = str(ev.get('FileName') or ev.get('Target_FileName') or ev.get('Target_Path') or '')
            if not fname:   
                 val = str(ev.get('Value', ''))
                 summ = str(ev.get('Summary', ''))
                 if ":\\" in summ: fname = summ 
                 elif ":\\" in val: fname = val
                 elif ":\\" in str(ev.get('Note', '')): fname = str(ev.get('Note', ''))
                 else: fname = 'Unknown'

            key = ts_sec # Key is just Time

            if key not in buffer:
                new_ev = ev.copy()
                act = str(ev.get('Value', '') or ev.get('Summary', ''))
                new_ev['Action_Set'] = {act} 
                new_ev['USN_Count'] = 1
                new_ev['File_Set'] = {fname} # Collect filenames
                buffer[key] = new_ev
            else:
                buffer[key]['USN_Count'] += 1
                act = str(ev.get('Value', '') or ev.get('Summary', ''))
                buffer[key]['Action_Set'].add(act)
                buffer[key]['File_Set'].add(fname)
                current_score = int(buffer[key].get('Score', 0) or 0)
                new_score = int(ev.get('Score', 0) or 0)
                buffer[key]['Score'] = max(current_score, new_score)

        # Flush Buffer
        for key, ev in buffer.items():
            count = ev.pop('USN_Count')
            files = ev.pop('File_Set', set())
            files.discard('Unknown')
            
            if count > 1:
                actions = "|".join(sorted(list(ev.pop('Action_Set'))))
                # Summarize files
                file_list = sorted(list(files))
                if len(file_list) > 3:
                    f_summary = f"{file_list[0]}, {file_list[1]}... (+{len(file_list)-2})"
                else:
                    f_summary = ", ".join(file_list)
                
                summary_text = f"**{count}x USN Events ({actions})**"
                if f_summary:
                    summary_text += f" - {f_summary}"

                
                # Update fields for display
                # For VisualIOCs (Section 4): Update Value, Tag
                if 'Value' in ev:
                    ev['Value'] = summary_text
                    ev['Tag'] = fname
                
                # For Timeline (Section 3): Update Summary, Source?
                # Template uses: {{ ev.Summary }}
                if 'Summary' in ev:
                    ev['Summary'] = summary_text
                    # Append filename to Summary or ensure it's visible?
                    # Section 3 columns: Time | Category | Summary | Source
                    # Put filename in Summary
                    ev['Summary'] = f"{summary_text} - {fname}"

            else:
                 ev.pop('Action_Set', None)
            
            condensed.append(ev)
            
        # Re-sort by Time to ensure order
        try:
            condensed.sort(key=lambda x: str(x.get('Time', '')))
        except:
            pass
            
        return condensed

    def _prepare_technical_findings(self, analyzer, origin_stories):
        # Wrapper for backward compatibility if needed, using raw visual_iocs
        return self._prepare_technical_findings_from_list(analyzer.visual_iocs, analyzer, origin_stories)

    def _prepare_stats(self, analyzer, analysis_data, dfs, refined_iocs=None):
        raw_count = analyzer.total_events_analyzed
        
        # Use refined IOCs if available, else raw
        target_iocs = refined_iocs if refined_iocs is not None else analyzer.visual_iocs
        crit_count = len(target_iocs)
        
        noise_removed = sum(analyzer.noise_stats.values()) if analyzer.noise_stats else 0
        total_processed = raw_count + noise_removed
        crit_ratio = (crit_count / total_processed * 100) if total_processed > 0 else 0
        
        crit_breakdown = []
        grouped = {}
        for ev in target_iocs:
            cat = self._get_event_category(ev)
            grouped.setdefault(cat, []).append(ev)
        for cat, items in grouped.items():
            max_score = max([int(x.get('Score', 0) or 0) for x in items])
            impact = "Evidence destruction" if "ANTI" in cat else "Evasion" if "TIME" in cat else "Compromise"
            crit_breakdown.append({"Type": cat, "Count": len(items), "MaxScore": max_score, "Impact": impact})
            
        med_breakdown = {}
        for m in analysis_data["medium_events"]:
             c = m.get('Category', 'Unknown')
             med_breakdown[c] = med_breakdown.get(c, 0) + 1
 
        return {
            "total_processed": total_processed,
            "crit_count": crit_count,
            "crit_ratio": crit_ratio,
            "noise_removed": noise_removed,
            "critical_breakdown": crit_breakdown,
            "medium_count": len(analysis_data["medium_events"]),
            "medium_breakdown": med_breakdown,
            "noise_stats": analyzer.noise_stats
        }

    def _prepare_recommendations(self, analyzer):
        rec = {"p0_evtlog": False, "p0_crx": False}
        if any("ANTI" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs):
            rec["p0_evtlog"] = True
        if any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in analyzer.visual_iocs):
            rec["p0_crx"] = True
        return rec

    # --- Legacy & Utility Methods ---

    def _get_event_category(self, ev):
        typ = str(ev.get('Type', '')).upper()
        tag = str(ev.get('Tag', '')).upper()
        if "ADS" in tag or "MASQUERADE" in tag: return "EXECUTION" # Classify ADS features as Execution
        if "SYSTEM_TIME" in tag or "TIME_CHANGE" in tag or "4616" in tag or "ROLLBACK" in tag: return "SYSTEM MANIPULATION"
        if "PHISH" in typ or "LNK" in typ: return "INITIAL ACCESS"
        if "WIPE" in typ or "ANTI" in typ or "ANTIFORENSICS" in tag: return "ANTI-FORENSICS"
        if "PERSIST" in typ or "SAM_SCAVENGE" in tag or "DIRTY_HIVE" in tag: return "PERSISTENCE"
        if "VULN" in typ or "VULN" in tag: return "VULNERABLE APP"
        if "REMOTE_ACCESS" in typ: return "REMOTE_ACCESS"
        if "EXEC" in typ or "RUN" in typ: return "EXECUTION"
        if "WEBSHELL" in typ or "WEBSHELL" in tag: return "WEBSHELL"
        if "LATERAL" in typ or "LATERAL" in tag: return "LATERAL MOVEMENT"
        if "TIMESTOMP" in typ: return "TIMESTOMP (FILE)"
        return "OTHER ACTIVITY"
    
    def _is_visual_noise(self, name):
        name = str(name).strip()
        if len(name) < 3: return True
        return False
        
    def _get_short_summary(self, ev):
        val = ev.get('Value', '')
        if not val or val == "Unknown":
            val = ev.get('Summary', '')
            if not val: val = str(ev.get('Tag', 'Event'))
        if "SYSTEM_TIME" in str(ev.get('Tag', '')) or "4616" in str(val): return "System Time Changed"
        if "\\" in val or "/" in val: val = os.path.basename(val.replace("\\", "/"))
        return val[:15] + ".." if len(val) > 15 else val

    def _render_mermaid_vertical_clustered(self, events):
        if not events: return "\n(No critical events found for visualization)\n"
        f = ["\n### 🏹 Attack Flow Visualization (Timeline)\n"]
        f.append("```mermaid")
        f.append("graph TD")
        f.append("    classDef init fill:#e63946,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef exec fill:#f4a261,stroke:#333,stroke-width:2px,color:black;")
        f.append("    classDef persist fill:#2a9d8f,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef anti fill:#264653,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef time fill:#a8dadc,stroke:#457b9d,stroke-width:4px,color:black;")
        f.append("    classDef phishing fill:#ff6b6b,stroke:#c92a2a,stroke-width:2px,color:white;")
        f.append("    classDef web fill:#d62828,stroke:#333,stroke-width:2px,color:white;")
        f.append("    classDef lateral fill:#e9c46a,stroke:#333,stroke-width:2px,color:black;")
        
        critical_events = [ev for ev in events if ev.get('Score', 0) >= 60 or "CRITICAL" in str(ev.get('Type', ''))]
        # [Refinement] Timeline Aggregation (Mermaid)
        sorted_events = self._compress_timeline_for_mermaid(critical_events)
        
        if not sorted_events: return "\n(No critical events found)\n"
        
        has_paradox = any("TIME_PARADOX" in str(ev.get('Type', '')) for ev in events)
        if has_paradox:
            f.append("    subgraph T_PRE [\"⚠️ TIME MANIPULATION\"]")
            f.append("        N_TP[\"⏪ <b>SYSTEM ROLLBACK DETECTED</b><br/>Time Paradox Anomaly\"]:::time")
            f.append("    end")
        
        subgraphs = []
        current_subgraph = {"nodes": [], "start_time": None, "end_time": None}
        def parse_dt(t_str):
            try: return datetime.fromisoformat(str(t_str).replace("Z", ""))
            except: return datetime.min
        last_dt = None
        node_id_counter = 0
        burst_buffer = [] 
        
        def flush_burst_buffer(buffer, target_list, counter):
            if not buffer: return counter
            first_ev = buffer[0]
            cat = self._get_event_category(first_ev)
            if len(buffer) >= 3 and ("INITIAL" in cat or "EXECUTION" in cat):
                node_id = f"N{counter}"; counter += 1
                start_t = str(buffer[0].get('Time', ''))[11:16]
                count = len(buffer)
                icon = "⚡"
                if "INITIAL" in cat: icon = "🎣"
                elif "EXEC" in cat: icon = "⚙️"
                short_summary = self._get_short_summary(first_ev)
                label = f"{start_t} {icon} {count}x Events<br/>({short_summary} etc.)"
                style = ":::exec"
                if "INITIAL" in cat: style = ":::phishing"
                target_list.append(f"{node_id}[\"{label}\"]{style}")
                return counter
            else:
                for ev in buffer:
                    node_id = f"N{counter}"; counter += 1
                    t_str = str(ev.get('Time', ''))[11:16]
                    s_sum = self._get_short_summary(ev)
                    ev_cat = self._get_event_category(ev)
                    icon = "🔹"; style = ":::default"
                    if "SYSTEM" in ev_cat: icon = "⏰"; style = ":::time"
                    elif "ANTI" in ev_cat: icon = "🗑️"; style = ":::anti"
                    elif "PERSIST" in ev_cat: icon = "⚓"; style = ":::persist"
                    elif "INITIAL" in ev_cat: icon = "🎣"; style = ":::init"
                    elif "WEBSHELL" in ev_cat: icon = "🕸️"; style = ":::web"
                    elif "LATERAL" in ev_cat: icon = "🐛"; style = ":::lateral"
                    elif "PHISH" in ev_cat: icon = "🎣"; style = ":::phishing"
                    label = f"{t_str} {icon} {s_sum}"
                    target_list.append(f"{node_id}[\"{label}\"]{style}")
                return counter

        for ev in sorted_events:
            if self._is_visual_noise(ev.get("Value", "")): continue
            dt = parse_dt(ev.get('Time', ''))
            if last_dt and (dt - last_dt).total_seconds() > 3600:
                node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                burst_buffer = []
                subgraphs.append(current_subgraph)
                current_subgraph = {"nodes": [], "start_time": dt, "end_time": dt}
            if current_subgraph["start_time"] is None: current_subgraph["start_time"] = dt
            current_subgraph["end_time"] = dt
            last_dt = dt
            if not burst_buffer: burst_buffer.append(ev)
            else:
                last_in_buff = burst_buffer[-1]
                last_buff_dt = parse_dt(last_in_buff.get('Time', ''))
                same_cat = self._get_event_category(ev) == self._get_event_category(last_in_buff)
                close_time = (dt - last_buff_dt).total_seconds() < 120 
                if same_cat and close_time: burst_buffer.append(ev)
                else:
                    node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
                    burst_buffer = [ev]
        node_id_counter = flush_burst_buffer(burst_buffer, current_subgraph["nodes"], node_id_counter)
        subgraphs.append(current_subgraph)

        sg_counter = 0; prev_sg_id = None
        if has_paradox: prev_sg_id = "T_PRE"
        for sg in subgraphs:
            if not sg["nodes"]: continue
            sg_id = f"T{sg_counter}"
            start_s = sg["start_time"].strftime("%H:%M")
            end_s = sg["end_time"].strftime("%H:%M")
            label = f"⏰ {start_s} - {end_s}"
            f.append(f"    subgraph {sg_id} [\"{label}\"]")
            for n in sg["nodes"]: f.append(f"        {n}")
            f.append("    end")
            if prev_sg_id:
                if prev_sg_id == "T_PRE": f.append(f"    N_TP --> {sg['nodes'][0].split('[')[0]}")
                else: f.append(f"    {prev_sg_id} --> {sg_id}")
            prev_sg_id = sg_id; sg_counter += 1
        f.append("```\n")
        return "\n".join(f)

    def _render_attack_chain_mermaid(self, visual_iocs):
        """
        [User Request] Convert to Sequence Diagram for better readability.
        Phases: Prep -> Phishing -> Exec -> Recon -> Anti
        """
        # 0. Localization Map
        is_jp = self.lang == 'jp'
        txt_map = {
            "p_prep": "🛠️ 準備段階" if is_jp else "🛠️ Prep/Tools",
            "p_phish": "🎣 初期侵入" if is_jp else "🎣 Initial Access",
            "p_exec": "⚙️ 実行・永続化" if is_jp else "⚙️ Execution",
            "p_recon": "🔍 偵察活動" if is_jp else "🔍 Recon/Exfil",
            "p_anti": "🧹 証拠隠滅" if is_jp else "🧹 Anti-Forensics",
            "note_time": "📅 タイムライン範囲: " if is_jp else "📅 Timeline Scope: ",
            "msg_prep": "攻撃ツールを事前配置 ({}件)" if is_jp else "Tools Staged ({} items)",
            "msg_phish": "LNK実行 / ペイロード展開" if is_jp else "LNKs/Payloads Triggered",
            "msg_exec": "不正プロセス実行 / 侵害活動" if is_jp else "Malicious Process Activity",
            "msg_recon": "情報持ち出し / 内部偵察" if is_jp else "Exfil & Cleanup Initiated",
            "note_anti": "⚠️ 証拠隠滅 / Timestomp検知" if is_jp else "⚠️ Evidence Wiping/Timestomp Detected"
        }

        # 1. Bucket Events by Phase
        prep_events = []
        phish_events = []
        exec_events = []
        recon_events = []
        anti_events = []
        
        for ioc in visual_iocs:
            tag = str(ioc.get('Tag', '')).upper()
            val = str(ioc.get('Value', '')).upper()
            typ = str(ioc.get('Type', '')).upper()
            
            # Classification Logic [v6.0 - Enhanced for Case7]
            # Anti-Forensics: Timestomp, Wipe, CCleaner
            if "TIMESTOMP" in tag or "WIPE" in tag or "ANTIFORENSIC" in tag or "CCLEANER" in val:
                anti_events.append(ioc)
            # Prep/Tools: SysInternals, Admin tools, Masquerade
            elif "SYSINTERNALS" in tag or "MASQUERADE" in tag or "ADMIN_TOOL" in tag or "UNCOMMON" in tag or "SYSINTERNALS" in val:
                prep_events.append(ioc)
            # Initial Access: Phishing, LNK
            elif "PHISHING" in tag or "LNK" in typ or "INIT_ACCESS" in tag:
                phish_events.append(ioc)
            # Recon: Discovery, Exfil, Network, LotL
            elif "RECON" in tag or "EXFIL" in tag or "NETWORK" in tag or "LOTL" in tag or "DISCOVERY" in tag:
                recon_events.append(ioc)
            # Execution: Run, Process, Exec
            elif "EXEC" in tag or "PROCESS" in tag or "RUN" in val or "EXECUTION" in typ or "EXEC" in typ:
                exec_events.append(ioc)
            # [Fix] Include Auth Failures / Brute Force in Execution
            elif "AUTH_FAILURE" in tag or "BRUTE_FORCE" in tag or "4625" in str(ioc.get('Note','')):
                exec_events.append(ioc)
            # [Fix] Include Persistence in Execution
            elif "PERSIST" in tag or "PERSISTENCE" in typ:
                exec_events.append(ioc)
            # Fallback: High score items go to execution
            elif int(ioc.get('Score', 0) or 0) >= 200:
                exec_events.append(ioc)
        
        # [Fix] Global Noise Filter for Mermaid
        # Exclude items with Score < 50 unless Critical
        prep_events = [e for e in prep_events if int(e.get('Score',0)) >= 50]
        # Allow Phishing (LNK) even if low score if meaningful? No, standard LNKs are noise.
        phish_events = [e for e in phish_events if int(e.get('Score',0)) >= 100 or "CRITICAL" in str(e.get('Tag',''))]
        exec_events = [e for e in exec_events if int(e.get('Score',0)) >= 100]
        # Recon: ssh-add-manual.htm often score 50. Filter it.
        recon_events = [e for e in recon_events if int(e.get('Score',0)) >= 100]
        # Anti: Keep even low score? Evidence destruction is rare.
        anti_events = [e for e in anti_events if int(e.get('Score',0)) >= 100]
                
        if not (prep_events or phish_events or exec_events or recon_events or anti_events):
            return ""

        f = []
        f.append("\n### 🏹 Attack Flow Visualization (Verb-Based Timeline)\n")
        f.append("```mermaid")
        f.append("sequenceDiagram")
        
        # [v6.1] Dynamic Participants based on actual events (Verb-Based)
        # Define Participants with Action Verbs
        txt_verb_map = {
            "p_download": "📥 Download" if not is_jp else "📥 ダウンロード",
            "p_execute": "⚡ Execute" if not is_jp else "⚡ 実行",
            "p_discover": "🔍 Discover" if not is_jp else "🔍 偵察",
            "p_cleanup": "🧹 Cleanup" if not is_jp else "🧹 隠滅"
        }
        
        f.append(f"    participant Download as {txt_verb_map['p_download']}")
        f.append(f"    participant Execute as {txt_verb_map['p_execute']}")
        f.append(f"    participant Discover as {txt_verb_map['p_discover']}")
        f.append(f"    participant Cleanup as {txt_verb_map['p_cleanup']}")
        
        # Note for Timeline
        dates = sorted([x.get('Time') for x in visual_iocs if x.get('Time')])
        if dates:
            start_d = dates[0].split('T')[0] if 'T' in str(dates[0]) else str(dates[0])[:10]
            end_d = dates[-1].split('T')[0] if 'T' in str(dates[-1]) else str(dates[-1])[:10]
            date_label = start_d if start_d == end_d else f"{start_d} ~ {end_d}"
            f.append(f"    Note over Download,Cleanup: 📅 {date_label}")



        # Generate Connections (Verb-Based Story Flow)
        # 1. Download Phase (Zone.Identifier, Prep tools)
        download_events = [e for e in prep_events + phish_events if any(k in str(e.get('Tag', '')) for k in ['ZONE', 'DOWNLOAD', 'PHISH'])]
        if not download_events:
            download_events = prep_events[:2]  # Fallback
        
        if download_events:
            sorted_dl = sorted(download_events, key=lambda x: str(x.get('Time', '')))
            f.append(f"    Download->>Execute: {'ツール・ペイロード取得' if is_jp else 'Payload Retrieved'}")
            self._render_group_with_date_split(f, "Download", sorted_dl, is_jp, "")
        
        # 2. Execute Phase (UserAssist, Amcache, Prefetch hits)
        if exec_events or prep_events:
            exec_combined = exec_events if exec_events else prep_events
            f.append(f"    Execute->>Discover: {'不正実行 / 侵害開始' if is_jp else 'Malicious Process Started'}")
            self._render_group_with_date_split(f, "Execute", exec_combined, is_jp, "")
            
        # 3. Discover Phase (Recon, LotL)
        if recon_events:
            f.append(f"    Discover->>Cleanup: {'内部偵察 / 情報収集' if is_jp else 'Internal Recon & Enum'}")
            self._render_group_with_date_split(f, "Discover", recon_events, is_jp, "")

        # 4. Cleanup Phase (Anti-Forensics, Timestomp)
        if anti_events:
            # For cleanup, we want to emphasize the gap if any
            f.append(f"    Cleanup-->>Cleanup: {'⚠️ 証拠隠滅' if is_jp else 'Evidence Destruction'}")
            self._render_group_with_date_split(f, "Cleanup", anti_events, is_jp, "")

        f.append("```\n")
        return "\n".join(f).replace("VOID_VISUALIZATION", "-")

    def _render_group_with_date_split(self, f, target_participant, events, is_jp, action_label_base):
        """
        Helper to invoke render notes, splitting by date if multiple dates exist.
        """
        if not events: return

        # Sort by time first
        events = sorted(events, key=lambda x: str(x.get('Time', '')))
        
        # Group by Date (YYYY-MM-DD)
        from collections import defaultdict
        date_groups = defaultdict(list)
        for e in events:
            t = str(e.get('Time', ''))
            # Robust date extraction
            if 'T' in t: d = t.split('T')[0]
            elif len(t) >= 10: d = t[:10]
            else: d = "Unknown_Date"
            date_groups[d].append(e)
        
        sorted_dates = sorted(date_groups.keys())
        
        # Render each date group
        last_displayed_dt_obj = None
        
        for d in sorted_dates:
            group_evs = date_groups[d]
            curr_dt_obj = None
            try: curr_dt_obj = datetime.strptime(d, "%Y-%m-%d")
            except: pass

            # [P4] Filter: Only show high-score or critical events in Mermaid notes
            CRITICAL_TAGS = ["WEBSHELL", "LATERAL", "ANTI", "EXFIL", "C2", "TIMESTOMP"]
            high_priority_evs = [e for e in group_evs if 
                int(e.get('Score', 0) or 0) >= 500 or 
                any(ct in str(e.get('Tag', '')).upper() for ct in CRITICAL_TAGS)]
            
            note_content = None

            # Determine if we display detailed notes, summary, or nothing
            if high_priority_evs:
                 # [Final Polish] Aggressive Note Compression
                 DISPLAY_LIMIT = 3
                 display_evs = high_priority_evs[:DISPLAY_LIMIT]
                 remain_count = len(high_priority_evs) - DISPLAY_LIMIT
                 
                 summary_html = self._summarize_with_time_simple(display_evs, max_items=DISPLAY_LIMIT)
                 if remain_count > 0:
                      summary_html += f"<br/>(...and {remain_count} more)"
                 note_content = summary_html


            
            # If no content to display, skip this date entirely (and don't update last_displayed_dt_obj)
            if not note_content:
                continue

            # [Feature] Timeline Gap Visualization (Coalesced)
            # Only visualize gap if we are about to display a new note
            if curr_dt_obj and last_displayed_dt_obj:
                delta = (curr_dt_obj - last_displayed_dt_obj).days
                # [Final Polish 3] Only show gaps > 30 days to reduce noise
                if delta > 30:
                     f.append(f"    Note over Download,Cleanup: ⏳ ... {delta} Days Gap ...")
            
            # Render the note
            f.append(f"    Note right of {target_participant}: {note_content}")
            
            # Update last displayed tracker
            if curr_dt_obj:
                 last_displayed_dt_obj = curr_dt_obj

    def _summarize_with_time_simple(self, evs, max_items=2):
        if not evs: return ""
        lines = []
        for i, e in enumerate(evs[:max_items]):
            val_raw = str(e.get('Value', ''))
            val = val_raw.split('\\')[-1]
            if len(val) > 20: val = val[:18] + ".."
            
            time_str = str(e.get('Time', ''))
            time_display = ""
            try:
                if 'T' in time_str:
                    dt_part = time_str.split('T')
                    date_part = dt_part[0].split('-') # YYYY-MM-DD
                    time_part = dt_part[1][:5] # HH:MM
                    time_display = f"{date_part[1]}/{date_part[2]} {time_part}"
                elif len(time_str) >= 16:
                    date_part = time_str[:10].split('-')
                    time_part = time_str[11:16]
                    time_display = f"{date_part[1]}/{date_part[2]} {time_part}"
                else:
                        time_display = time_str[:16]
            except:
                    time_display = time_str

            source = ""
            note = str(e.get('Note', ''))
            tag = str(e.get('Tag', '')).upper()
            
            # [Fix] Critical: Robust check for 'system' labeling
            val_clean = val_raw.strip().lower()
            score_int = int(e.get('Score', 0) or 0)
            
            if "AUTH_FAILURE" in tag or "BRUTE_FORCE_DETECTED" in tag:
                val = "AUTH_FAILURE" 
                if "BRUTE_FORCE_DETECTED" in tag: val += " (Brute Force)"
            elif val_clean == "system":
                 # Robust check: if score is critical (300), force rewrite
                 if score_int >= 300:
                     val = "AUTH_FAILURE (EID:4625)"
                 elif "Logon Failure" in note or "4625" in note:
                     val = "AUTH_FAILURE"
            
            if 'UserAssist' in note: source = "[UA]"
            elif 'Amcache' in note: source = "[AC]"
            elif 'Prefetch' in note: source = "[PF]"
            elif 'Zone' in note: source = "[ZI]"
            
            line = f"{time_display} {val}{source}" if time_display else f"{val}{source}"
            lines.append(line)
        
        if len(evs) > max_items:
            lines.append(f"(+{len(evs) - max_items} more)")
        
        return "<br/>".join(lines)


    def _render_plutos_section_text(self, dfs, analyzer=None):
        f_mock = []
        class MockFile:
            def write(self, s): f_mock.append(s)
        self._write_plutos_section(MockFile(), dfs, analyzer)
        return "".join(f_mock)

    def _render_plutos_section_text_OLD_UNUSED(self, dfs):
        # Kept for reference if needed, but logic moved to _render_plutos_section_text
        pass

    def _write_plutos_section(self, f, dfs, analyzer=None):
        f.write("\n## 🌐 5. 重要ネットワークおよび持ち出し痕跡 (Critical Network & Exfiltration)\n")
        f.write("PlutosGateエンジンにより検出された、**データの持ち出し**、**メールデータの不正コピー**、および**高リスクな外部通信**の痕跡。\n\n")
        f.write("### 🚨 5.1 検出された重大な脅威 (Critical Threats Detected)\n")
        critical_table = self._generate_critical_threats_table(dfs, analyzer)
        f.write(critical_table + "\n\n")
        net_map = self._generate_critical_network_map(dfs, analyzer)
        if net_map:
            f.write("### 🗺️ 5.2 ネットワーク相関図 (Critical Activity Map)\n")
            f.write(net_map + "\n\n")
            f.write("> **Note:** 赤色は外部への持ち出しやC2通信、オレンジ色は内部への横展開を示唆します。\n\n")
        else:
            f.write("※ 視覚化可能なネットワークトポロジーは検出されませんでした。\n\n")
        f.write("---\n")

    def _generate_critical_threats_table(self, dfs, analyzer=None):
        rows = []
        
        # 1. Existing Plutos Logic (SRUM/Exfil) - Kept as is
        srum_df = dfs.get("Plutos_Srum")
        if srum_df is not None and srum_df.height > 0:
            try:
                if "Heat_Score" in srum_df.columns:
                    df = srum_df.filter(pl.col("Heat_Score").cast(pl.Int64, strict=False) >= 60)
                    for r in df.iter_rows(named=True):
                        ts = str(r.get("Timestamp", "")).split(".")[0]
                        proc = str(r.get("Process", "")).split("\\")[-1]
                        sent_mb = int(r.get("BytesSent", 0) or 0) // 1024 // 1024
                        rows.append({
                            "Time": ts, "Icon": "📤", "Verdict": f"**{r.get('Plutos_Verdict', 'HIGH_HEAT')}**",
                            "Details": f"Proc: {proc}<br>Sent: {sent_mb} MB", "Ref": "See: Plutos_Report_srum.csv"
                        })
            except: pass

        exfil_df = dfs.get("Plutos_Exfil")
        if exfil_df is not None and exfil_df.height > 0:
            try:
                for r in exfil_df.iter_rows(named=True):
                    ts = str(r.get("Timestamp", "")).split(".")[0]
                    fname = r.get("FileName", "Unknown")
                    url = str(r.get("URL", ""))[:30] + "..." if r.get("URL") else ""
                    rows.append({
                        "Time": ts, "Icon": "🚨", "Verdict": "**EXFIL_CORRELATION**",
                        "Details": f"File: **{fname}**<br>URL: {url}", "Ref": "See: Plutos_Report_exfil_correlation.csv"
                    })
            except: pass

        # 2. [v5.3] Inject Analyzer Findings (Lateral, Recon, Sensitive Doc)
        if analyzer and analyzer.visual_iocs:
             # [Fix] Reuse EXTREME_NOISE patterns for filtering this section too
             EXTREME_NOISE = [
                "_none_", "_10.0.", "_amd64_", "_x86_", "~31bf3856ad364e35~",
                "windows\\winsxs", "windowsapps\\", "infusedapps\\", 
                "8wekyb3d8bbwe", "deletedalluserpackages", "nativeimages_", 
                "\\assembly\\gac", "microsoftsolitaire", "mspaint_", "microsoftedge_8wekyb3d8bbwe",
                "microsoft.windows.cortana", "appmodel-runtime", "contentdeliverymanager", "devicesearchcache",
                # XAMPP Legitimate Components
                "xampp\\php\\pear", "xampp\\apache\\manual", "xampp\\tomcat\\webapps\\docs",
                "xampp\\tomcat\\webapps\\examples", "xampp\\src\\", "xampp\\licenses", "xampp\\locale",
                "xampp\\php\\docs", "xampp\\cgi-bin", "\\pear\\docs", "\\pear\\tests",
                # XAMPP Extended Noise
                "xampp\\perl\\lib", "xampp\\perl\\vendor", "filezillaftp\\source",
                "apache\\icons", "mercurymail\\", "mysql\\data\\",
                "phpmyadmin\\js\\", "phpmyadmin\\libraries\\", "phpmyadmin\\themes\\",
                "webalizer\\", "sendmail\\",
                # XAMPP Additional Noise (Tomcat, Static, Sessions)
                "xampp\\tmp\\sess_", "tomcat\\webapps\\manager", "tomcat\\webapps\\host-manager",
                "tomcat\\webapps\\root", "phpmyadmin\\doc\\", "htdocs\\img\\", "security\\htdocs\\",
                # XAMPP Dashboard & Docs
                "htdocs\\dashboard\\", "htdocs\\docs\\", "dashboard\\images\\", "dashboard\\css\\", "dashboard\\docs\\",
                # XAMPP Libraries & Extras
                "php\\extras\\", "php\\tests\\", "perl\\bin\\", "perl\\site\\",
                # XAMPP Apache/MySQL Config & Locales
                "apache\\include\\", "apache\\modules\\", "mysql\\share\\", "phpmyadmin\\locale\\",
                # XAMPP Test & Misc
                "webdav\\", "\\flags\\", "\\install\\", "phpids\\tests\\",
                # Browser Cache & DVWA Static Resources
                "content.ie5\\", "dvwa\\dvwa\\images\\", "dvwa\\dvwa\\css\\", "dvwa\\external\\",
                # XAMPP System Libraries (Loader noise)
                "apache\\bin\\iconv\\", "php\\ext\\", "tomcat\\lib\\",
                # MySQL Metadata (Running service artifacts)
                ".frm", ".myd", ".myi", "performance_schema\\",
                # XAMPP Icons & Static Assets
                "xampp\\img\\", "hackable\\users\\", "favicon.ico",
                # AGGRESSIVE NOISE FILTERS (Server process loader artifacts)
                "xampp\\apache\\bin\\", "xampp\\mysql\\bin\\", "xampp\\php\\", "xampp\\tomcat\\bin\\",
                # Library/Binary extensions
                ".dll", ".jar", ".so", ".chm", ".hlp", ".class",
                # Documentation noise
                "readme.txt", "license.txt", "install.txt", "changes.txt",
                # MySQL system tables
                "information_schema\\", "mysql\\mysql\\", "catalina\\"
             ]
             
             for ioc in analyzer.visual_iocs:
                 tag = str(ioc.get("Tag", "")).upper()
                 val = str(ioc.get("Value", ""))
                 val_lower = val.lower()
                 score = int(ioc.get("Score", 0) or 0)
                 
                 # [Fix] Skip EXTREME_NOISE in this section as well
                 if any(xp in val_lower for xp in EXTREME_NOISE):
                     continue
                 
                 # Criteria for Section 5.1 inclusion
                 is_target = False
                 icon = "❓"; verdict = "UNKNOWN"
                 
                 if "LATERAL" in tag or "UNC_" in tag:
                     is_target = True; icon = "🐛"; verdict = "**LATERAL_MOVEMENT**"
                 elif "INTERNAL_RECON" in tag:
                     is_target = True; icon = "🔍"; verdict = "**INTERNAL_RECON**"
                 elif "SENSITIVE" in tag:
                     is_target = True; icon = "🔐"; verdict = "**SENSITIVE_ACCESS**"
                 elif "EXFIL" in tag or "DATA_EXFIL" in str(ioc.get("Type", "")):
                     is_target = True; icon = "📤"; verdict = "**DATA_EXFILTRATION**"
                 
                 if is_target:
                     t_str = str(ioc.get("Time", "")).replace("T", " ")[:19]
                     
                     # [P2'] IE Cache Aggregation (Skip individual addition, will handle bulk later)
                     # Identify scattered IE cache files by Tag or Path pattern
                     if "INTERNAL_RECON_WEB" in tag or "CONTENT.IE5" in val.upper():
                         # Store separately, do not add to 'rows' yet
                         if not hasattr(self, '_ie_cache_pool'): self._ie_cache_pool = []
                         self._ie_cache_pool.append(ioc)
                         continue

                     # [P4'] dsadd.exe Enrichment
                     if "dsadd" in val_lower:
                         val = f"{val} ⚠️ **(AD User Manipulation Tool - PrivEsc Prep)**"
                     
                     rows.append({
                         "Time": t_str, "Icon": icon, "Verdict": verdict,
                         "Details": f"{val}", "Ref": "Timeline Analysis", "Tag": tag
                     })

        # [P2'] Inject Aggregated IE Cache Entry
        if hasattr(self, '_ie_cache_pool') and self._ie_cache_pool:
            ie_pool = getattr(self, '_ie_cache_pool')
            first_time = str(ie_pool[0].get("Time", "")).replace("T", " ")[:19]
            count = len(ie_pool)
            rows.append({
                "Time": first_time, "Icon": "🌐", "Verdict": "**SUSPICIOUS_WEB_CACHE**",
                "Details": f"📦 **Suspicious IE Cache Files x{count}** (Potential external resource loading)",
                "Ref": f"Aggregated {count} web artifacts"
            })

        if not rows: return self.txt.get('plutos_no_activity', "No suspicious network activity detected.\n")

        rows.sort(key=lambda x: x["Time"])
        
        # [v6.5] Timestamp Aggregation Algorithm
        # Group by second, compress INTERNAL_RECON noise, preserve critical keywords
        CRITICAL_KEYWORDS = ["password", "shell", "cmd", "whoami", "credentials", "webshell", "c99", "backdoor"]
        NOISE_EXTENSIONS = [".bat", ".xml", ".csv", ".csm", ".ibd", ".opt", ".php", ".pyd", ".manifest"]
        
        aggregated_rows = []
        i = 0
        while i < len(rows):
            current = rows[i]
            t_sec = current["Time"][:19]  # Group by second
            
            # Check if this is a critical item that should NOT be compressed
            is_critical = any(kw in current["Details"].lower() for kw in CRITICAL_KEYWORDS)
            
            if is_critical or current["Verdict"] not in ["**INTERNAL_RECON**"]:
                # Keep critical items and non-INTERNAL_RECON items as-is
                aggregated_rows.append(current)
                i += 1
                continue
            
            # For INTERNAL_RECON, check if we can aggregate with following entries
            group = [current]
            j = i + 1
            while j < len(rows):
                next_row = rows[j]
                next_t_sec = next_row["Time"][:19]
                
                # Stop if different timestamp or different verdict type
                if next_t_sec != t_sec or next_row["Verdict"] != current["Verdict"]:
                    break
                
                # Don't aggregate critical items
                if any(kw in next_row["Details"].lower() for kw in CRITICAL_KEYWORDS):
                    break
                
                group.append(next_row)
                j += 1
            
            if len(group) >= 3:
                # Compress into single row: "Noise x(count) (examples)"
                examples = [g["Details"].split("\\")[-1].split("/")[-1][:25] for g in group[:3]]
                compressed = f"📦 Noise x{len(group)} ({', '.join(examples)}...)"
                aggregated_rows.append({
                    "Time": t_sec, "Icon": "🔇", "Verdict": "**COMPRESSED_NOISE**",
                    "Details": compressed, "Ref": f"Aggregated {len(group)} entries"
                })
                i = j  # Skip all grouped items
            else:
                # Not enough to compress, output individually
                for g in group:
                    aggregated_rows.append(g)
                i = j

        # [P0] Top 20 Limit - Show only most important entries
        MAX_DISPLAY = 20
        critical_rows = [r for r in aggregated_rows if any(kw in r.get("Details", "").lower() for kw in CRITICAL_KEYWORDS)]
        other_rows = [r for r in aggregated_rows if r not in critical_rows]
        
        # Prioritize critical, then by time
        display_rows = critical_rows[:10] + other_rows[:MAX_DISPLAY - len(critical_rows[:10])]
        remaining_count = len(aggregated_rows) - len(display_rows)

        md = "| Time / Period | Verdict | Summary | Reference |\n|---|---|---|---|\n"
        for row in display_rows:
            md += f"| {row['Time']} | {row['Icon']} {row['Verdict']} | {row['Details']} | {row['Ref']} |\n"
        
        if remaining_count > 0:
            md += f"\n> 📦 **その他 {remaining_count} 件の検出は省略されました。** 詳細は `IOC_Full.csv` を参照してください。\n"
        
        return md
    
    def _generate_critical_network_map(self, dfs, analyzer=None):
        """Generate Mermaid network topology diagram from IOC data"""
        if not analyzer or not analyzer.visual_iocs:
            return ""
        
        # Extract network-related IOCs
        unc_shares = set()  # UNC paths -> (IP, share_name, files)
        remote_ips = set()
        remote_tools = []
        exfil_tools = []
        web_targets = []
        
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        unc_pattern = re.compile(r'\\\\([\d\.]+|[a-zA-Z0-9_\-]+)\\([^\\]+)')
        
        for ioc in analyzer.visual_iocs:
            val = str(ioc.get("Value", ""))
            path = str(ioc.get("Path", ""))
            tag = str(ioc.get("Tag", "")).upper()
            ioc_type = str(ioc.get("Type", "")).upper()
            combined = val + " " + path
            
            # Extract UNC paths
            unc_match = unc_pattern.search(combined)
            if unc_match:
                ip_or_host = unc_match.group(1)
                share_name = unc_match.group(2)
                # Extract file info
                file_part = combined.split(share_name + "\\")[-1] if share_name in combined else ""
                unc_shares.add((ip_or_host, share_name, file_part[:30] if file_part else ""))
                remote_ips.add(ip_or_host)
            
            # Extract standalone IPs
            ip_match = ip_pattern.search(combined)
            if ip_match:
                ip_cand = ip_match.group(1)
                # [Case 6 Noise Fix] Filter out logic-level IPs (1.0.0.0) or version numbers
                if "127.0.0.1" not in ip_cand and "0.0.0.0" not in ip_cand:
                    try:
                        p1 = int(ip_cand.split('.')[0])
                        # Allow valid public DNS, otherwise ignore < 10 (likely version numbers)
                        if p1 >= 10 or ip_cand in ["1.1.1.1", "8.8.8.8", "8.8.4.4"]:
                             remote_ips.add(ip_cand)
                    except: pass
            
            # Categorize tools
            val_lower = val.lower()
            if "REMOTE_ACCESS" in ioc_type or "REMOTE_ACCESS" in tag:
                if "putty" in val_lower or "ssh" in val_lower or "plink" in val_lower:
                    remote_tools.append(val.split("\\")[-1].split("/")[-1])
            
            if "DATA_EXFIL" in ioc_type or "EXFIL" in tag:
                if any(x in val_lower for x in ["dd.exe", "ssh-add", "wget", "curl", "nc.exe", "netcat"]):
                    exfil_tools.append(val.split("\\")[-1].split("/")[-1])
            
            # Web reconnaissance
            if "xampp" in val_lower or "phpmyadmin" in val_lower or "http" in val_lower:
                web_targets.append(val[:30])
        
        # Need at least some network activity to generate map
        if not remote_ips and not unc_shares:
            return ""
        
        # Build Mermaid diagram
        lines = ["```mermaid", "graph LR"]
        
        # Host node with users
        primary_user = getattr(self, 'primary_user', 'User') or 'User'
        # Get joker user if exists
        users_str = primary_user
        for ioc in analyzer.visual_iocs:
            tag = str(ioc.get("Tag", "")).upper()
            if "NEW_USER_CREATION" in tag:
                new_user = str(ioc.get("Value", "")).split("\\")[-1].split("/")[-1]
                if new_user and new_user.lower() not in users_str.lower():
                    users_str = f"{primary_user}/{new_user}"
                    break
        
        lines.append(f'    A["{self.hostname}<br/>{users_str}"]')
        
        node_id = ord('B')
        
        # Add remote IPs/shares
        for ip in list(remote_ips)[:3]:  # Limit to 3 IPs
            node = chr(node_id)
            node_id += 1
            
            # Find share info for this IP
            share_info = ""
            files_on_share = []
            for unc_ip, share_name, file_part in unc_shares:
                if unc_ip == ip:
                    share_info = share_name
                    if file_part:
                        files_on_share.append(file_part)
            
            if share_info:
                lines.append(f'    {node}["{ip}<br/>{share_info}"]')
                lines.append(f'    A -->|SMB| {node}')
                
                # Add files from share
                if files_on_share:
                    file_node = chr(node_id)
                    node_id += 1
                    files_display = "<br/>".join(files_on_share[:3])
                    lines.append(f'    {file_node}["{files_display}"]')
                    lines.append(f'    {node} --> {file_node}')
            else:
                lines.append(f'    {node}["{ip}"]')
                lines.append(f'    A -->|Network| {node}')
        
        # Add remote access tools
        if remote_tools:
            tool_node = chr(node_id)
            node_id += 1
            unique_tools = list(set(remote_tools))[:3]
            tools_display = "<br/>".join(unique_tools)
            lines.append(f'    {tool_node}["🔧 Remote Tools<br/>{tools_display}"]')
            lines.append(f'    A -->|SSH/Remote| {tool_node}')
        
        # Add exfil tools
        if exfil_tools:
            exfil_node = chr(node_id)
            node_id += 1
            unique_exfil = list(set(exfil_tools))[:3]
            exfil_display = "<br/>".join(unique_exfil)
            lines.append(f'    {exfil_node}["⚠️ Exfil Prep<br/>{exfil_display}"]')
            lines.append(f'    A -->|Exfil Prep| {exfil_node}')
            # Style as warning
            lines.append(f'    style {exfil_node} fill:#f96')
        
        # Add web targets if detected
        if web_targets and list(remote_ips):
            # Link web activity to first IP
            first_ip_node = 'B'  # Assuming first IP is node B
            lines.append(f'    A -->|HTTP| {first_ip_node}')
        
        lines.append("```")
        
        return "\n".join(lines)

    def _extract_dual_run_count(self, ioc, dfs):
        ua_count = "N/A"; pf_count = "N/A"
        text_sources = [ioc.get("Value", ""), ioc.get("Summary", ""), ioc.get("Action", ""), ioc.get("Target_Path", "")]
        for text in text_sources:
            if not text: continue
            match = re.search(r"\(Run:\s*(\d+)\)", str(text), re.IGNORECASE)
            if match: ua_count = match.group(1); break
        return f"UA: {ua_count} | PF: {pf_count}"

    def export_pivot_config(self, pivot_seeds, path, primary_user):
        if not pivot_seeds: return
        
        # Group by category
        categorized = {}
        for seed in pivot_seeds:
            cat = seed.get("Category", "GENERAL")
            if cat not in categorized:
                categorized[cat] = []
            # Remove Category from individual entries to avoid redundancy
            entry = {k: v for k, v in seed.items() if k != "Category"}
            categorized[cat].append(entry)
        
        # Limit each category to top 10
        for cat in categorized:
            categorized[cat] = categorized[cat][:10]
        
        # Priority order for categories
        priority_order = ["CRITICAL_PHISHING", "CRITICAL_RECON", "CRITICAL_ANTI_FORENSICS", "CRITICAL_LATERAL", "GENERAL"]
        ordered_targets = {}
        for cat in priority_order:
            if cat in categorized and categorized[cat]:
                ordered_targets[cat] = categorized[cat]
        # Add any remaining categories
        for cat in categorized:
            if cat not in ordered_targets and categorized[cat]:
                ordered_targets[cat] = categorized[cat]
        
        config = {
            "Case_Context": {
                "Hostname": self.hostname,
                "Primary_User": primary_user,
                "Generated_At": datetime.now().isoformat()
            },
            "Deep_Dive_Targets": ordered_targets
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"    -> [Lachesis] Pivot Config generated: {path}")
        except Exception as e:
            print(f"    [!] Failed to export Pivot Config: {e}")

    def export_json_grimoire(self, analysis_result, analyzer, json_path, primary_user):
        serializable_events = []
        for ev in analysis_result.get("events", []):
            serializable_events.append({
                "Time": str(ev.get('Time')),
                "Category": ev.get('Category'),
                "Summary": ev.get('Summary'),
                "Source": ev.get('Source')
            })
        grimoire_data = {
            "Metadata": {
                "Host": self.hostname, 
                "Case": "Investigation", 
                "Primary_User": primary_user, 
                "Generated_At": datetime.now().isoformat()
            },
            "Verdict": {
                "Flags": list(analysis_result.get("verdict_flags", [])), 
                "Lateral_Summary": analysis_result.get("lateral_summary", "")
            },
            "Timeline": serializable_events,
            "IOCs": {"File": analyzer.visual_iocs, "Network": []}
        }
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(grimoire_data, f, indent=2, ensure_ascii=False)
            print(f"    -> [Chimera Ready] JSON Grimoire saved: {json_path}")
        except Exception as e:
            print(f"    [!] Failed to export JSON Grimoire: {e}")