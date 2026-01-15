"""
UserReporter - Per-User Activity Report Generator
Part of SkiaHelios Lachesis Module
"""
import os
import re
from pathlib import Path
from datetime import datetime

class UserActivityReporter:
    def __init__(self, hostname):
        self.hostname = hostname

    def generate(self, events, output_file_path):
        """
        Generate dedicated reports for NEW_USER_CREATION targets.
        Args:
            events (list): List of event dictionaries (refined_iocs or all_events)
            output_file_path (str): Path to the main report file (used for dir resolution)
        """
        if not events:
            return

        output_dir = Path(output_file_path).parent

        # 1. Identify Target Users
        user_buckets = self._bucket_events_by_malicious_user(events)

        if not user_buckets:
            print("    [-] No malicious user activities found for separate reporting.")
            return

        # 2. Generate Reports
        for user, user_events in user_buckets.items():
            self._write_user_report(user, user_events, output_dir)

    def _bucket_events_by_malicious_user(self, events):
        # [Refactor] Load safe users from Intel module
        from tools.lachesis.intel import IntelManager
        
        buckets = {}
        SAFE_USERS = IntelManager.get_safe_users()
        
        for ev in events:
            user_candidate = None
            tags = str(ev.get('Tag', '')).upper()
            path = str(ev.get('Path', '') or ev.get('Target_Path', '') or ev.get('Value', '')).lower()
            
            # Priority 1: Explicit Tag
            if "NEW_USER_CREATION" in tags:
                user_candidate = str(ev.get('User', '')).split("\\")[-1]
            
            # Priority 2: Path Heuristics (Recover missing tags)
            # Look for \Users\<Name>\ pattern
            if not user_candidate and "users" in path:
                match = re.search(r"users[\\/]([^\\/]+)", path)
                if match:
                    extracted = match.group(1)
                    if extracted.upper() not in SAFE_USERS:
                        user_candidate = extracted

            # If a suspicious user context is found, add to bucket
            if user_candidate:
                # Normalize
                user_candidate = user_candidate.strip()
                if not user_candidate: continue
                
                # Check Safe List again just in case
                if user_candidate.upper() in SAFE_USERS: continue

                if user_candidate not in buckets:
                    buckets[user_candidate] = []
                buckets[user_candidate].append(ev)
            
        return buckets

    def _write_user_report(self, user, events, output_dir):
        if not events: return
        
        # Sort by time
        events.sort(key=lambda x: str(x.get('Time', '')))
        
        total_count = len(events)
        # Filter Critical: Score >= 500
        critical_events = [e for e in events if int(e.get('Score', 0) or 0) >= 500]
        
        # Sanitize filename
        safe_user = "".join([c for c in user if c.isalnum() or c in (' ', '_', '-')]).strip()
        report_name = f"{self.hostname}_{safe_user}_Activity_Report.md"
        report_path = output_dir / report_name
        
        print(f"    -> [Lachesis] Generating User Report: {report_name} ({total_count} events)")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# 👤 User Activity Report: {user}\n\n")
            f.write(f"> **Target Host:** {self.hostname}\n")
            f.write(f"> **User Identity:** {user} (Newly Created / Suspicious)\n")
            f.write(f"> **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("---\n\n")
            
            # Summary
            f.write("## 📊 Executive Summary\n")
            f.write(f"- **Total Activities:** {total_count}\n")
            f.write(f"- **Critical Findings:** {len(critical_events)}\n")
            f.write(f"- **Detection Tags:** `NEW_USER_CREATION`\n\n")
            
            # Critical Table
            f.write("## 🚨 Critical Findings (Score >= 500)\n")
            f.write("| Time (UTC) | Activity / Path | Score | Tags |\n")
            f.write("|---|---|---|---|\n")
            
            if critical_events:
                for ev in critical_events:
                    self._write_table_row(f, ev)
            else:
                f.write("| - | No critical events found | - | - |\n")
            
            f.write("\n---\n\n")
            
            # Full Timeline (Filtered Noise)
            f.write("## 📅 Full Activity Timeline\n")
            f.write("| Time (UTC) | Category | Summary | Score |\n")
            f.write("|---|---|---|---|\n")
            
            for ev in events:
                # Basic noise filter for the report lines
                path = str(ev.get('Value', '') or ev.get('Path', '')).lower()
                if "appdata" in path and "packages" in path and int(ev.get('Score',0)) < 500:
                    continue # Skip bulk noise in full timeline too
                self._write_timeline_row(f, ev)

    def _write_table_row(self, f, ev):
        time = str(ev.get('Time', ''))[:19].replace('T', ' ')
        val = self._get_display_value(ev)
        score = ev.get('Score', 0)
        
        # [Fix] Clean Tags - hide internal/redundant tags
        raw_tags = str(ev.get('Tag', '')).replace(' ', '').split(',')
        ignore = ["MFT_ENTRY", "USN_ENTRY", "NEW_USER_CREATION", "LIVE", "A", "B", "C", "D", "E", 
                  "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", 
                  "U", "V", "W", "X", "Y", "Z", "_"]
        tags = [t for t in raw_tags if t and t not in ignore and len(t) > 1]
        
        if tags:
            tag_str = ", ".join(list(set(tags))[:2])  # Max 2 tags for compact table
        else:
            tag_str = "-"
        
        f.write(f"| {time} | `{val}` | {score} | {tag_str} |\n")

    def _write_timeline_row(self, f, ev):
        time = str(ev.get('Time', ''))[:19].replace('T', ' ')
        cat = ev.get('Category', 'Unknown')
        summary = self._get_display_value(ev)
        # Escape pipes for markdown table
        summary = summary.replace("|", "\|")
        if len(summary) > 100: summary = summary[:97] + "..."
        score = ev.get('Score', 0)
        f.write(f"| {time} | {cat} | {summary} | {score} |\n")

    def _get_display_value(self, row):
        # Determine best display value
        candidates = [
            row.get("FileName"), 
            row.get("Target_Path"), 
            row.get("CommandLine"), 
            row.get("Payload"), 
            row.get("Message"), 
            row.get("Action"), 
            row.get("Value")
        ]
        for c in candidates:
            val = str(c).strip()
            if val and val not in ["", "None", "N/A", "Unknown"]:
                # [Fix] Smart Truncate for User Report
                if len(val) > 80:
                    parts = val.replace('/', '\\').split('\\')
                    if len(parts) > 4:
                        return f"...\\{parts[-3]}\\{parts[-2]}\\{parts[-1]}"
                    else:
                        return val[:40] + "..." + val[-35:]
                return val
        return "Unknown Activity"