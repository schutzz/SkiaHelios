# SkiaHelios フォレンジック解析報告書

- **Generated:** 2025-12-25 11:22:43.903915
- アーティファクト間の相関分析に特化した自動生成報告書。

## 0. 調査手法および凡例
SkiaHeliosは、分散した証拠を紐付け、攻撃者の意図を再構成します。

### Modules:
- **Chaos**: マスタータイムラインの構築
- **Chronos**: MFTタイムスタンプ矛盾の検知
- **AION**: MFT相関型永続化メカニズムの探索
- **Plutos**: 情報持ち出しトラッキング
- **Sphinx**: 難読化スクリプトの解読

### Tag Legend:
- `TIMESTOMP_BACKDATE`: $SI時刻が$FN時刻より古い矛盾
- `USER_PERSISTENCE`: HKCU(ユーザー権限)での永続化検知
- `WMI_PERSISTENCE`: WMIを利用したファイルレス潜伏

## 1. エグゼクティブ・サマリー

| モジュール | リスクレベル | 検知件数 |
|---|---|---|
| Plutos | 【警告】要調査 | 0 |
| Sphinx | 【警告】要調査 | 7 |

## 2. 異常イベント・ストーリーライン
> 各モジュールが検知した不審なイベントを時系列で構成しています。

| 発生時刻 | 検知モジュール | イベント内容 |
|---|---|---|
| 2025-12-21 11:51:52.9071767 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:52.9108124 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:52.9135893 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:52.9219339 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:52.9232563 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:52.9248439 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21 11:51:54.0237174 | ****Sphinx**** | OBFUSCATION_DECODED: [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh...... |
| 2025-12-21T11:37:01.815568000 | ****Execution**** | MALICIOUS_EXECUTION: cmd.exe (Amcache) |
| 2025-12-21T11:52:07.000000000 | ****Execution**** | MALICIOUS_EXECUTION: timestomp.exe (Prefetch) |
| 2025-12-21T11:52:09.345705000 | ****Execution**** | MALICIOUS_EXECUTION: timestomp.exe (Amcache) |
| 2025-12-21T11:52:28.000000000 | ****Execution**** | MALICIOUS_EXECUTION: beacon.exe (Prefetch) |
| 2025-12-21T11:52:29.294286000 | ****Execution**** | MALICIOUS_EXECUTION: beacon.exe (Amcache) |

## 3. 高優先度検知詳細


### 難読化解除結果 (Sphinx)
| Score | Tags | Hint |
|---|---|---|
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |
| **150** | ATTACK_SIG_DETECTED | [FORCE DECODE] Attack Keyword Found: HostApplication=C:\WINDOWS\System32\WindowsPowerSh... |

---
*End of SkiaHelios Report.*