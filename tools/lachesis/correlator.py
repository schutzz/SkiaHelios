import polars as pl

class CrossCorrelationEngine:
    """
    [Logic Layer] Rule-based Cross-Correlation Engine
    Pandoraの発見事項(IOC)と、Plutos/Chronosの証拠データを突き合わせ、
    確信度(Confidence)をブーストさせる専門モジュール。
    """
    def __init__(self, intel_module):
        self.intel = intel_module
        # YAMLからルールをロード (なければ空リスト)
        self.rules = self.intel.get('correlation_rules', [])
        # データキャッシュ (SRUMなどの参照用)
        self.data_cache = {}

    def load_evidence(self, dfs):
        """参照用データをメモリにロード・辞書化して高速化"""
        # 1. SRUM (Plutos) のキャッシュ構築
        if dfs.get('Plutos_Srum') is not None:
            srum_map = {}
            # プロセス名で集計 (BytesSent)
            # Processカラムは "C:\Windows\System32\curl.exe" のようなフルパスの場合もあるのでファイル名もキーにする
            for row in dfs['Plutos_Srum'].iter_rows(named=True):
                proc_full = str(row.get("Process", "")).lower()
                proc_name = proc_full.split("\\")[-1]
                sent = int(row.get("BytesSent", 0) or 0)
                
                # フルパスとファイル名の両方で検索できるようにする
                if proc_name in srum_map: srum_map[proc_name] += sent
                else: srum_map[proc_name] = sent
                
            self.data_cache['Plutos_Srum'] = srum_map
            
        # 今後 Firewall, DNS, EventLog などが増えたらここに追加

    def apply_rules(self, visual_iocs):
        """IOCリストに対してルールを適用し、スコア修正などを破壊的に行う"""
        if not self.rules: 
            return visual_iocs

        count = 0
        for ioc in visual_iocs:
            # タグと値を正規化
            ioc_tags = str(ioc.get("Tag", "")).upper()
            ioc_val = str(ioc.get("Value", "")).lower()

            for rule in self.rules:
                # --- A. Trigger Check (条件合致) ---
                triggers = rule.get('triggers', {})
                target_tags = triggers.get('tags', [])
                
                # タグがいずれか一致するか (OR条件)
                if not any(t in ioc_tags for t in target_tags):
                    continue

                # --- B. Validation (証拠確認) ---
                validator = rule.get('validator', {})
                source_name = validator.get('source')
                
                # キャッシュからデータを取得
                source_data = self.data_cache.get(source_name)
                if not source_data: continue

                # 照合 (ファイル名 vs プロセス名)
                metric_val = source_data.get(ioc_val, 0)
                
                # 閾値チェック
                threshold = validator.get('threshold', 0)
                operator = validator.get('operator', '>')
                
                is_hit = False
                if operator == '>' and metric_val > threshold: is_hit = True
                elif operator == '>=' and metric_val >= threshold: is_hit = True
                
                if not is_hit: continue

                # --- C. Action (評価更新) ---
                self._apply_action(ioc, rule.get('action', {}), metric_val, rule.get('id', 'Unknown'))
                count += 1
                
        if count > 0:
            print(f"    [+] Correlation Engine: Boosted {count} IOCs based on cross-evidence.")
        
        return visual_iocs

    def _apply_action(self, ioc, action, metric_val, rule_id):
        # スコア更新
        if 'score_override' in action:
            ioc['Score'] = max(int(ioc.get('Score', 0)), action['score_override'])
        elif 'score_min' in action:
            ioc['Score'] = max(int(ioc.get('Score', 0)), action['score_min'])
        
        # タグ追加
        if 'tag_append' in action:
            new_tags = action['tag_append']
            current_tags = ioc.get('Tag', '')
            # 重複防止
            tag_set = set(current_tags.split(','))
            add_set = set(new_tags.split(','))
            if not add_set.issubset(tag_set):
                ioc['Tag'] = (current_tags + "," + new_tags).strip(',')

        # Note/Insight 追加 (テンプレート展開)
        fmt_data = {"value": metric_val, "value_mb": metric_val // 1024 // 1024}
        
        if 'note_append' in action:
            note = action['note_append'].format(**fmt_data)
            if note not in ioc.get('Note', ''):
                ioc['Note'] = (ioc.get('Note', '') + note)
        
        if 'insight_template' in action:
            insight = action['insight_template'].format(**fmt_data)
            current_insight = ioc.get('Insight', '')
            if insight not in current_insight:
                ioc['Insight'] = (current_insight + "\n\n" + insight).strip()

    def determine_verdict(self, iocs):
        """
        [Logic Layer] Dynamic Verdict Engine
        IOCの分布状況から、インシデントの性質（Verdict）を判定する。
        (Moved from analyzer.py)
        """
        verdict_flags = set()
        summary = []
        
        # 集計
        counts = {
            "TIMESTOMP": 0, "WIPER": 0, "RANSOM": 0, "LATERAL": 0, 
            "EXFIL": 0, "MASQUERADE": 0, "PHISHING": 0
        }
        
        for ioc in iocs:
            tags = str(ioc.get("Tag", "")).upper()
            score = int(ioc.get("Score", 0))
            
            if "TIMESTOMP" in tags: counts["TIMESTOMP"] += 1
            if "WIPE" in tags or "SDELETE" in tags: counts["WIPER"] += 1
            if "RANSOM" in tags or "ENCRYPT" in tags: counts["RANSOM"] += 1
            if "LATERAL" in tags or "REMOTE" in tags or "PSEXEC" in tags: counts["LATERAL"] += 1
            if "DATA_EXFIL" in tags: counts["EXFIL"] += 1
            if "MASQUERADE" in tags: counts["MASQUERADE"] += 1
            if "PHISHING" in tags: counts["PHISHING"] += 1

        # 判定ロジック (Logic)
        if counts["RANSOM"] > 0:
            verdict_flags.add("RANSOMWARE_ACTIVITY")
            summary.append(f"ランサムウェア活動 ({counts['RANSOM']} events)")
            
        if counts["TIMESTOMP"] >= 3 or counts["WIPER"] >= 1:
            verdict_flags.add("ANTI_FORENSICS_HEAVY")
            summary.append("高度な証拠隠滅活動")

        if counts["LATERAL"] >= 2:
            verdict_flags.add("LATERAL_MOVEMENT_ACTIVE")
            summary.append("ネットワーク横展開の痕跡")
            
        if counts["EXFIL"] >= 1:
            verdict_flags.add("DATA_EXFILTRATION")
            summary.append("情報の持ち出し")
            
        if counts["PHISHING"] >= 1:
            verdict_flags.add("PHISHING_ENTRY")
            summary.append("フィッシングによる初期侵入")

        # 最終サマリー生成
        # lateral_summary という変数名が不自然(User Request snippet used it).
        # But return looks like `verdict_flags, lateral_summary`.
        # I'll stick to variable name `lateral_summary` for compatibility if analyzer expects it,
        # though user asked for `verdict_flags, lateral_summary` returned.
        verdict_text = " / ".join(summary) if summary else "No Critical Activity Patterns Detected"
        
        return verdict_flags, verdict_text
