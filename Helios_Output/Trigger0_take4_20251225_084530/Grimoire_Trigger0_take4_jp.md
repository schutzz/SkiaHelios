# SkiaHelios フォレンジック解析報告書

- **Generated:** 2025-12-25 08:45:32.029538
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
## 2. 異常イベント・ストーリーライン
> 各モジュールが検知した不審なイベントを時系列で構成しています。

| 発生時刻 | 検知モジュール | イベント内容 |
|---|---|---|
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 10:40:22 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 11:28:02 | **Plutos** | Exfil/Access: msedge.exe (NORMAL_APP_ACCESS) |
| 2025-12-21 11:30:22 | **Plutos** | Exfil/Access: onedrive.exe (SYSTEM_INTERNAL_ACTIVITY) |

## 3. 高優先度検知詳細


---
*End of SkiaHelios Report.*