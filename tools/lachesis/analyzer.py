import re
from datetime import datetime, timedelta

class LachesisAnalyzer:
    def __init__(self, intel_module, enricher_module):
        self.intel = intel_module
        self.enricher = enricher_module
        self.visual_iocs = []
        self.pivot_seeds = []
        self.infra_ips_found = set()
        self.noise_stats = {}
        self.total_events_analyzed = 0

    def process_events(self, analysis_result, dfs):
        raw_events = analysis_result.get("events", [])
        self.total_events_analyzed = len(raw_events)
        self.noise_stats = self.intel.noise_stats # Share stats dict

        high_crit_times = []
        critical_events = []
        medium_events = []

        # 1. Event Filtering & Scoring
        for ev in raw_events:
            try: score = int(float(ev.get('Criticality', 0)))
            except: score = 0
            summary = ev.get('Summary', '')
            tag = str(ev.get('Tag', '')).upper()
            is_dual = self.intel.is_dual_use(summary)
            
            is_crit_std = False
            if score >= 200: is_crit_std = True
            elif is_dual and score >= 80: is_crit_std = True
            elif "CRITICAL" in str(ev.get('Category', '')).upper(): is_crit_std = True
            elif "CRITICAL" in tag or "ACTIVE" in tag: is_crit_std = True
            
            force_include_tags = ["TIME_PARADOX", "MASQUERADE", "PHISHING", "SUSPICIOUS_CMDLINE", "ROLLBACK"]
            if any(k in tag for k in force_include_tags):
                is_crit_std = True
            
            if is_crit_std: critical_events.append(ev)
            elif score >= 80: medium_events.append(ev)

            # High Crit Time Calculation
            chk_score = score
            for k in ['Threat_Score', 'Chronos_Score', 'AION_Score']:
                try: 
                    s = int(float(ev.get(k, 0)))
                    if s > chk_score: chk_score = s
                except: pass
            
            chk_tag = tag + str(ev.get('Threat_Tag', "")).upper()
            chk_name = str(ev.get('FileName', "") or ev.get('Ghost_FileName', "") or ev.get('Target_FileName', "") or summary).lower()
            
            if chk_score >= 200 or "CRITICAL" in chk_tag or "MASQUERADE" in chk_tag or "TIMESTOMP" in chk_tag or "PHISHING" in chk_tag or "PARADOX" in chk_tag or self.intel.is_dual_use(chk_name):
                t_val = ev.get('Time') or ev.get('Ghost_Time_Hint') or ev.get('Last_Executed_Time')
                dt = self.enricher.parse_time_safe(t_val)
                if dt and dt.year >= 2016:  
                    high_crit_times.append(dt)

        # 2. Extract Visual IOCs
        self.visual_iocs = []
        self._extract_visual_iocs_from_pandora(dfs)
        self._extract_visual_iocs_from_chronos(dfs)
        self._extract_visual_iocs_from_aion(dfs)
        self._extract_visual_iocs_from_events(raw_events)
        
        # 3. Generate Pivot Seeds
        self._generate_pivot_seeds()
        
        # 4. Refine Time Range
        force_include_types = ["TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", "TIMESTOMP", "CREDENTIALS"]
        for ioc in self.visual_iocs:
            ioc_type = str(ioc.get("Type", "")).upper()
            if any(k in ioc_type for k in force_include_types):
                ioc_time = ioc.get("Time", "")
                dt = self.enricher.parse_time_safe(ioc_time)
                if dt and dt.year >= 2016:
                    high_crit_times.append(dt)

        time_range = "Unknown Range (No Critical Events)"
        if high_crit_times:
            high_crit_times = sorted(set(high_crit_times))
            core_start = min(high_crit_times) - timedelta(hours=3)
            core_end = max(high_crit_times) + timedelta(hours=3)
            time_range = f"{core_start.strftime('%Y-%m-%d %H:%M')} 〜 {core_end.strftime('%H:%M')} (UTC)"

        return {
            "critical_events": critical_events,
            "medium_events": medium_events,
            "time_range": time_range,
            "phases": [critical_events] if critical_events else []
        }

    def _extract_visual_iocs_from_chronos(self, dfs):
        if dfs.get('Chronos') is not None:
            df = dfs['Chronos']
            cols = df.columns
            score_col = "Chronos_Score" if "Chronos_Score" in cols else "Threat_Score"
            if score_col in cols:
                try:
                    df_sorted = df.sort(score_col, descending=True)
                    for row in df_sorted.iter_rows(named=True):
                        fname = row.get("FileName") or ""
                        path = row.get("ParentPath") or ""
                        score = int(float(row.get(score_col, 0)))
                        
                        bypass_reason = None
                        is_trusted_loc = self.intel.is_trusted_system_path(path)
                        is_dual = self.intel.is_dual_use(fname)

                        if "ROLLBACK" in str(row.get("Anomaly_Time", "")):
                            bypass_reason = "🚨 SYSTEM TIME ROLLBACK DETECTED 🚨"
                            if not fname and path: fname = f"System Artifact ({path})"
                            self.intel.log_noise("TIME PARADOX", f"{fname} triggered Rollback Alert")
                            self._add_unique_visual_ioc({
                                "Type": "TIME_PARADOX", 
                                "Value": fname if fname else "Unknown", 
                                "Path": path, 
                                "Note": str(row.get("Anomaly_Time", "")), 
                                "Time": str(row.get("si_dt", "") or row.get("UpdateTimestamp", "")),
                                "Reason": bypass_reason,
                                "Score": score 
                            })
                            continue

                        extra_info = {}
                        timeline_df = dfs.get('Timeline')
                        if is_dual or "TIMESTOMP" in str(row.get("Threat_Tag", "")):
                             _, _, _, is_executed = self.enricher.enrich_from_timeline(fname, timeline_df)
                             extra_info["Execution"] = is_executed

                        if is_dual:
                            bypass_reason = "Dual-Use Tool [DROP]" 
                        elif score >= 220:
                            if is_trusted_loc:
                                self.intel.log_noise("Trusted Path (Update)", fname)
                                continue
                            else:
                                bypass_reason = "High Score (Timestomp) [DROP]"
                        
                        if self.intel.is_noise(fname, path):
                             self.intel.log_noise("Explicit Noise Filter", fname)
                             continue

                        if bypass_reason:
                             if "False Positive" in bypass_reason or "NOISE" in bypass_reason: continue
                        elif score < 200: continue 
                        
                        if not bypass_reason: bypass_reason = "High Score (>200)"
                        self._add_unique_visual_ioc({
                            "Type": "TIMESTOMP", "Value": fname, "Path": path, "Note": "Time Anomaly", 
                            "Time": str(row.get("Anomaly_Time", "")), 
                            "Reason": bypass_reason, 
                            "Score": score,
                            "Extra": extra_info
                        })
                except: pass

    def _extract_visual_iocs_from_pandora(self, dfs):
        if dfs.get('Pandora') is not None:
            df = dfs['Pandora']
            timeline_df = dfs.get('Timeline') 
            
            if "Threat_Score" in df.columns:
                try:
                    df_sorted = df.sort("Threat_Score", descending=True)
                    for row in df_sorted.iter_rows(named=True):
                        fname = row.get("Ghost_FileName", "")
                        path = row.get("ParentPath", "")
                        tag = str(row.get("Threat_Tag", "")).upper()
                        score = int(float(row.get("Threat_Score", 0)))

                        bypass_reason = None
                        is_trusted_loc = self.intel.is_trusted_system_path(path)

                        if "MASQUERADE" in tag: bypass_reason = "Critical Criteria (CRITICAL_MASQUERADE) [DROP]"
                        elif "PHISH" in tag: bypass_reason = "Critical Criteria (PHISHING) [DROP]"
                        elif "BACKDOOR" in tag: bypass_reason = "Backdoor Detected [DROP]"
                        elif "CREDENTIALS" in tag and score >= 200: bypass_reason = "Credential Dump [DROP]"
                        
                        elif is_trusted_loc:
                            self.intel.log_noise("Trusted Path (Update)", fname)
                            continue
                        
                        if self.intel.is_noise(fname, path):
                             self.intel.log_noise("Explicit Noise Filter", fname)
                             continue

                        elif self.intel.is_dual_use(fname): bypass_reason = "Dual-Use Tool [DROP]"
                        elif "TIMESTOMP" in tag: bypass_reason = "Timestomp [DROP]"
                        elif score >= 250: bypass_reason = "Critical Score [DROP]"

                        if bypass_reason: 
                            pass
                        elif score < 200: continue

                        if not bypass_reason: bypass_reason = "High Confidence"
                        clean_name = fname.split("] ")[-1]
                        
                        extra_info = {}
                        final_tag = tag
                        
                        if ".lnk" in fname.lower():
                            target_path, timeline_tag, args, _ = self.enricher.enrich_from_timeline(fname, timeline_df)
                            
                            if target_path: extra_info["Target_Path"] = target_path
                            if args: extra_info["Arguments"] = args
                            
                            if "DEFCON" in clean_name.upper() or "BYPASS" in clean_name.upper():
                                extra_info["Risk"] = "SECURITY_TOOL_MASQUERADE"

                            if timeline_tag:
                                merged_tags = set(tag.split(",") + timeline_tag.split(","))
                                merged_tags.discard("")
                                final_tag = ",".join(list(merged_tags))
                        
                        self._add_unique_visual_ioc({
                            "Type": final_tag,
                            "Value": clean_name, 
                            "Path": path, 
                            "Note": "File Artifact", 
                            "Time": str(row.get("Ghost_Time_Hint", "")), 
                            "Reason": bypass_reason,
                            "Extra": extra_info,
                            "Score": score
                        })
                except: pass

    def _extract_visual_iocs_from_aion(self, dfs):
         if dfs.get('AION') is not None:
            df = dfs['AION']
            if "AION_Score" in df.columns:
                try:
                    for row in df.iter_rows(named=True):
                        try: score = int(float(row.get("AION_Score", 0)))
                        except: score = 0
                        if score >= 50:
                            name = row.get("Target_FileName")
                            if not self.intel.is_noise(name, row.get("Full_Path", "")):
                                self._add_unique_visual_ioc({
                                    "Type": "PERSISTENCE", "Value": name, "Path": row.get("Full_Path"), "Note": "Persist", 
                                    "Time": str(row.get("Last_Executed_Time", "")), "Reason": "Persistence",
                                    "Score": score
                                })
                except: pass

    def _extract_visual_iocs_from_events(self, events):
        re_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        infra_ips = ["10.0.2.15", "10.0.2.2", "127.0.0.1", "0.0.0.0", "::1"]
        for ev in events:
            content = ev['Summary'] + " " + str(ev.get('Detail', ''))
            ips = re_ip.findall(content)
            for ip in ips:
                if ip in infra_ips or ip.startswith("127."): 
                    self.infra_ips_found.add(ip); continue
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        p1 = int(parts[0]); p2 = int(parts[1])
                        if p1 < 10 and ip != "1.1.1.1" and ip != "8.8.8.8" and ip != "8.8.4.4": continue 
                    except: continue
                self._add_unique_visual_ioc({
                    "Type": "IP_TRACE", "Value": ip, "Path": "Network", "Note": f"Detected in {ev['Source']}"
                })
            
            is_dual = self.intel.is_dual_use(ev.get('Summary', ''))
            tag = str(ev.get('Tag', '')).upper()
            is_af = "ANTI_FORENSICS" in tag
            score = ev.get('Criticality', 0)

            if (ev['Criticality'] >= 90 or is_dual or is_af) and (ev['Category'] == 'EXEC' or ev['Category'] == 'ANTI'):
                kws = ev.get('Keywords', [])
                if kws:
                    kw = str(kws[0]).lower()
                    if not self.intel.is_noise(kw):
                        if is_af:
                            type_label = "ANTI_FORENSICS"
                            reason_label = "Evidence Destruction"
                        elif is_dual:
                            type_label = "DUAL_USE_TOOL"
                            reason_label = "Dual-Use Tool [DROP]"
                        else:
                            type_label = "EXECUTION"
                            reason_label = "Execution"

                        self._add_unique_visual_ioc({
                            "Type": type_label, "Value": kws[0], "Path": "Process", "Note": f"Execution ({ev['Source']})",
                            "Reason": reason_label,
                            "Time": ev.get('Time'),
                            "Score": score,
                            "Summary": ev.get('Summary', '')
                        })

    def _add_unique_visual_ioc(self, ioc_dict):
        if self.intel.is_noise(ioc_dict["Value"], ioc_dict.get("Path", "")): return
        for existing in self.visual_iocs:
            if existing["Value"] == ioc_dict["Value"] and existing["Type"] == ioc_dict["Type"]: return
        self.visual_iocs.append(ioc_dict)

    def _generate_pivot_seeds(self):
        for ioc in self.visual_iocs:
            self.pivot_seeds.append({
                "Target_File": ioc["Value"],
                "Target_Path": ioc.get("Path", ""),
                "Reason": ioc.get("Reason", ioc["Type"]),
                "Timestamp_Hint": ioc.get("Time", "")
            })

    def is_force_include_ioc(self, ioc):
        force_keywords = [
            "TIME_PARADOX", "CRITICAL_MASQUERADE", "CRITICAL_PHISHING", 
            "SUSPICIOUS_CMDLINE", "CRITICAL_SIGMA", "ROLLBACK", "BACKDOOR"
        ]
        ioc_type = str(ioc.get('Type', '')).upper()
        reason = str(ioc.get('Reason', '')).upper()
        
        if any(k in ioc_type for k in force_keywords):
            return True
        if any(k in reason for k in force_keywords):
            return True
        if "DUAL-USE" in reason or "DUAL_USE" in ioc_type:
            return True
        if "TIMESTOMP" in ioc_type:
            return True
        return False
    
    def generate_ioc_insight(self, ioc):
        ioc_type = str(ioc.get('Type', '')).upper()
        
        if "ANTI_FORENSICS" in ioc_type:
            return "🚨 **Evidence Destruction**: 証拠隠滅ツールです。実行回数やタイムスタンプを確認してください。"
        
        val = str(ioc.get('Value', ''))
        val_lower = val.lower()
        reason = str(ioc.get('Reason', '')).upper()
        path = str(ioc.get('Path', ''))

        if "EXECUTION_CONFIRMED" in ioc_type:
            return "🚨 **Confirmed**: このツールは実際に実行された痕跡があります。調査優先度：高"
        
        elif "TIME_PARADOX" in ioc_type or "ROLLBACK" in reason:
            rb_sec = "Unknown"
            if "Rollback:" in val:
                match = re.search(r"Rollback:\s*(-?\d+)", val)
                if match: rb_sec = match.group(1)
            return f"USNジャーナルの整合性分析により、システム時刻の巻き戻し(約{rb_sec}秒)を検知しました。これは高度なアンチフォレンジック活動を示唆します。"
        
        elif "MASQUERADE" in ioc_type or ".crx" in val_lower:
            masq_app = "正規アプリケーション"
            if "adobe" in path.lower(): masq_app = "Adobe Reader"
            elif "microsoft" in path.lower(): masq_app = "Microsoft Office"
            elif "google" in path.lower(): masq_app = "Google Chrome"
            return f"{masq_app}のフォルダに、無関係なChrome拡張機能(.crx)が配置されています。これは典型的なPersistence（永続化）手法です。"
        
        elif ".lnk" in val_lower and ("SUSPICIOUS" in ioc_type or "PHISHING" in ioc_type or "PS_" in ioc_type or "CMD_" in ioc_type or "MSHTA" in ioc_type):
            insights = []
            extra = ioc.get('Extra', {})
            target = extra.get('Target_Path', '')
            args = extra.get('Arguments', '')
            risk = extra.get('Risk', '')

            intel_desc = self.intel.match_intel(val)
            if intel_desc:
                insights.append(intel_desc)

            if not target:
                if "Target:" in val: target = val.split("Target:")[-1].strip()
                elif "🎯" in val: target = val.split("🎯")[-1].strip()
            
            if target:
                insights.append(f"🎯 **Target**: `{target}`")
                
                if "cmd.exe" in target.lower() or "powershell" in target.lower():
                     insights.append("⚠️ **Critical**: OS標準シェルを悪用した攻撃の起点です。")
                elif ".exe" in target.lower() or ".bat" in target.lower() or ".vbs" in target.lower():
                     insights.append("⚠️ **High**: 実行可能ファイルを呼び出すショートカットです。")

            if args:
                args_disp = (args[:100] + "...") if len(args) > 100 else args
                insights.append(f"📝 **Args**: `{args_disp}`")
                
                if "-enc" in args.lower() or "-encoded" in args.lower():
                    insights.append("🚫 **Encoded**: Base64エンコードされたPowerShellコマンドを検知。即座に解析が必要です。")
                if "-windowstyle hidden" in args.lower() or "-w hidden" in args.lower():
                    insights.append("🕶️ **Stealth**: ユーザーからウィンドウを隠蔽するフラグを確認。")
            else:
                 if "-enc" in target.lower():
                      insights.append("🚫 **Encoded**: ターゲットパス内にエンコードされたコマンドを確認。")

            if risk == "SECURITY_TOOL_MASQUERADE":
                insights.append("🎭 **Masquerade**: セキュリティツールやカンファレンス資料(DEFCON等)への偽装が疑われます。")

            if insights:
                return "<br/>".join(insights)
            elif "PHISHING" in ioc_type:
                return "不審なショートカットファイルが作成されました。フィッシング攻撃の可能性があります。"
            else:
                return "不審なショートカットファイルを検知しました。"
        
        elif "PHISHING" in ioc_type:
            return "フィッシング活動に関連するアーティファクトを検知しました。"
        
        elif "TIMESTOMP" in ioc_type:
            tool_name = val.split()[0] if val else "Unknown"
            return f"`{tool_name}` のタイムスタンプに不整合（Timestomp）を確認。攻撃ツールを隠蔽しようとした痕跡です。"
        
        elif "CREDENTIALS" in ioc_type:
            return "認証情報の窃取または不正ツールの配置を検知しました。"
        
        elif "COMMUNICATION_CONFIRMED" in reason or "COMMUNICATION_CONFIRMED" in ioc_type:
            return "🚨 ブラウザ履歴との照合により、**実際にネットワーク通信が成功した痕跡**を確認しました。C2サーバへのビーコン送信、またはペイロードダウンロードの可能性が極めて高いです。"
        
        return None