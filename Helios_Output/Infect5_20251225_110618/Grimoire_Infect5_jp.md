# SkiaHelios フォレンジック解析報告書

- **Generated:** 2025-12-25 11:06:20.200968
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
| Chronos | 【警告】要調査 | 4 |
| Plutos | 【警告】要調査 | 0 |
## 2. 異常イベント・ストーリーライン
> 各モジュールが検知した不審なイベントを時系列で構成しています。

| 発生時刻 | 検知モジュール | イベント内容 |
|---|---|---|
| 2024-04-01 07:22:07.6534661 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.dll |
| 2024-04-01 16:33:09.6173245 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.resources.dll |
| 2024-04-01 16:37:17.0014995 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.ni.dll |
| 2024-04-01 16:37:17.4233365 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in TaskScheduler.ni.dll |

## 3. 高優先度検知詳細


---
*End of SkiaHelios Report.*