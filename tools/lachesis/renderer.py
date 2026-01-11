import json
import re
import polars as pl
import os
from datetime import datetime, timedelta
from pathlib import Path
from tools.lachesis.intel import TEXT_RES

from tools.lachesis.narrator import NarrativeGenerator

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
        
        print(f"[*] Lachesis v5.5 (Templated) is weaving the Grimoire into {out_file}...")

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
                new_phases = []
                for phase in analysis_data['phases']:
                    # Apply condensation to each timeline phase
                    new_phase = self._condense_usn_events(phase)
                    new_phases.append(new_phase)
                analysis_data['phases'] = new_phases

            # [Optimization] Apply Grouping & Noise Reduction Globally
            # This ensures Section 4 (Detailed Findings), Section 7 (IOCs), and Stats are consistent.
            refined_iocs = self._group_all_iocs(analyzer.visual_iocs)
            
            # [Fix] Global Clean of VOID bug (Targeting the typo version specifically)
            # This ensures Tables (Section 7) are clean, not just the diagram.
            for ioc in refined_iocs:
                t_str = str(ioc.get('Time', ''))
                if "VOID_VISUALIZA" in t_str: # Matches both correct and typo versions
                     ioc['Time'] = "-"

            # [Fix] Pre-calculate technical findings using refined IOCs (passing analyzer)
            tech_findings = self._prepare_technical_findings_from_list(refined_iocs, analyzer, origin_stories)
            init_access = tech_findings.get("INITIAL ACCESS", [])
            high_lnks = [i for i in init_access if i.get("Insight")]
            gen_lnks = [i for i in init_access if not i.get("Insight")]

            context = {
                "txt": self.txt,
                "hostname": self.hostname,
                "metadata": metadata,
                "analysis_data": analysis_data,
                "now": datetime.now().strftime('%Y-%m-%d'),
                "dynamic_verdict": analyzer.determine_dynamic_verdict(),
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
                "plutos_section": self._render_plutos_section_text(dfs_for_ioc),
                "stats": self._prepare_stats(analyzer, analysis_data, dfs_for_ioc, refined_iocs),
                "recommendations": self._prepare_recommendations(analyzer),
                "all_iocs": refined_iocs 
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

    def _group_all_iocs(self, iocs):
        # Flattened grouping for Section 7
        grouped_iocs = []
        
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

            # --- PHASE 0: Score Cut (Noise Reduction) ---
            # User Request: Score < 90 Cut (Drop low confidence items)
            # Exceptions: CRITICAL, TIMESTOMP tags
            
            rescue_tags = ["CRITICAL", "TIMESTOMP", "KNOWN_WEBSHELL", "C2", "RANSOM", "ROOTKIT"]
            has_rescue_tag = any(t in tag for t in rescue_tags)
            
            # [Debug Verbose]
            if "USN" in tag:
                with open("debug_verbose.log", "a", encoding="utf-8") as f:
                     import os
                     if os.path.getsize("debug_verbose.log") < 50000: # Increase limit
                         f.write(f"USN Item: Cat={cat} Tag={tag} Val={val} Sc={score} Time={ev.get('Time')}\n")
            
            # Strict Drop for low scores unless rescued
            if score < 90 and not has_rescue_tag:
                 continue

            # --- PHASE 1: Grouping Logic ---
            
            should_group = False
            group_key = ""
            
            # 1.1 VULNERABLE APP (Bulk Grouping)
            if "VULNERABLE APP" in cat:
                should_group = True
                group_key = f"VULN|{tag}" 

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

    # --- Context Helper Methods ---

    def _get_attack_methods(self, analyzer):
        t = self.txt
        visual_iocs = analyzer.visual_iocs
        has_paradox = any("TIME_PARADOX" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_masquerade = any("MASQUERADE" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_phishing = any("PHISHING" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_timestomp = any("TIMESTOMP" in str(ioc.get('Type', '')) for ioc in visual_iocs)
        has_anti = any("ANTI" in str(ioc.get('Type', '')) or "ANTIFORENSICS" in str(ioc.get('Tag', '')) for ioc in visual_iocs)

        methods = []
        if has_phishing: methods.append(t.get('attack_phishing', "Phishing"))
        if has_masquerade: methods.append(t.get('attack_masquerade', "Masquerading"))
        if has_timestomp: methods.append(t.get('attack_timestomp', "Timestomping"))
        if has_paradox: methods.append(t.get('attack_paradox', "Time Paradox"))
        if has_anti: methods.append(t.get('attack_anti', "Anti-Forensics"))
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
            row.get("Reg_Key"),
            row.get("Service_Name"), # [v5.7.1] Smart Formatting: Service
            row.get("Payload"),
            row.get("Message"),      # [v5.7.1] Smart Formatting: EventMsg
            row.get("Action"),
            row.get("Value")         # [Fix] Fallback to Value (e.g. URL)
        ]
        for c in candidates:
            if c and str(c).strip() not in ["", "None", "N/A"]:
                return str(c).strip()
        return "Unknown Activity"

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
            "VULNERABLE APP": "🔓 Vulnerable Application"
        }
        
        temp_groups = {}
        for ev in events:
            if ev.get('Score', 0) < 50 and "CRITICAL" not in str(ev.get('Type', '')): continue
            cat = self._get_event_category(ev)
            if cat not in temp_groups: temp_groups[cat] = []
            
            impact = "-"
            extra = ev.get('Extra', {})
            tag = str(ev.get('Tag', ''))
            if "SYSTEM_TIME" in tag or "4616" in tag or "TIME_PARADOX" in str(ev.get('Type', '')):
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
        # [Fix] Ensure ADS/Masquerade items are included even if Score logic misses them
        high_conf_events = [ioc for ioc in ioc_list if analyzer.is_force_include_ioc(ioc) or "ANTI" in str(ioc.get("Type", "")) or "ADS" in str(ioc.get("Tag", "")) or "MASQUERADE" in str(ioc.get("Tag", ""))]
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
        last_dt_obj = None
        
        for d in sorted_dates:
            group_evs = date_groups[d]
            
            # [Feature] Timeline Gap Visualization
            try:
                curr_dt_obj = datetime.strptime(d, "%Y-%m-%d")
                if last_dt_obj:
                    delta = (curr_dt_obj - last_dt_obj).days
                    if delta > 1:
                        # Insert Gap Note
                        f.append(f"    Note over Download,Cleanup: ⏳ ... {delta} Days Gap ...")
                last_dt_obj = curr_dt_obj
            except: pass

            # Create a summary for this date group
            summary_html = self._summarize_with_time_simple(group_evs)
            f.append(f"    Note right of {target_participant}: {summary_html}")

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


    def _render_plutos_section_text(self, dfs):
        f_mock = []
        class MockFile:
            def write(self, s): f_mock.append(s)
        self._write_plutos_section(MockFile(), dfs)
        return "".join(f_mock)

    def _render_plutos_section_text_OLD_UNUSED(self, dfs):
        # Kept for reference if needed, but logic moved to _render_plutos_section_text
        pass

    def _write_plutos_section(self, f, dfs):
        f.write("\n## 🌐 5. 重要ネットワークおよび持ち出し痕跡 (Critical Network & Exfiltration)\n")
        f.write("PlutosGateエンジンにより検出された、**データの持ち出し**、**メールデータの不正コピー**、および**高リスクな外部通信**の痕跡。\n\n")
        f.write("### 🚨 5.1 検出された重大な脅威 (Critical Threats Detected)\n")
        critical_table = self._generate_critical_threats_table(dfs)
        f.write(critical_table + "\n\n")
        net_map = self._generate_critical_network_map(dfs)
        if net_map:
            f.write("### 🗺️ 5.2 ネットワーク相関図 (Critical Activity Map)\n")
            f.write(net_map + "\n\n")
            f.write("> **Note:** 赤色は外部への持ち出しやC2通信、オレンジ色は内部への横展開を示唆します。\n\n")
        else:
            f.write("※ 視覚化可能なネットワークトポロジーは検出されませんでした。\n\n")
        f.write("---\n")

    def _generate_critical_threats_table(self, dfs):
        rows = []
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

        if not rows: return self.txt.get('plutos_no_activity', "No suspicious network activity detected.\n")

        rows.sort(key=lambda x: x["Time"])
        md = "| Time / Period | Verdict | Summary | Reference |\n|---|---|---|---|\n"
        for row in rows:
            md += f"| {row['Time']} | {row['Icon']} {row['Verdict']} | {row['Details']} | {row['Ref']} |\n"
        return md
    
    def _generate_critical_network_map(self, dfs):
        return "" # Simplified, Plutos integration verified in Phase 1

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
        config = {
            "Case_Context": {
                "Hostname": self.hostname,
                "Primary_User": primary_user,
                "Generated_At": datetime.now().isoformat()
            },
            "Deep_Dive_Targets": pivot_seeds[:20]
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