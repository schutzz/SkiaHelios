# SkiaHelios フォレンジック解析報告書

- **Generated:** 2025-12-25 10:07:48.524910
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
| Chronos | 【警告】要調査 | 124 |
| Plutos | 【警告】要調査 | 0 |
## 2. 異常イベント・ストーリーライン
> 各モジュールが検知した不審なイベントを時系列で構成しています。

| 発生時刻 | 検知モジュール | イベント内容 |
|---|---|---|
| 2024-04-01 16:38:45.3562498 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.GamePlatform.Services.dll |
| 2024-04-01 16:38:45.5436838 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinRTAdapter.dll |
| 2024-04-01 16:38:45.5436838 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.App.dll |
| 2024-04-01 16:38:46.2156280 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.App.exe |
| 2024-04-01 16:38:46.2312603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in CommunityToolkit.AppServices.dll |
| 2024-04-01 16:38:46.2468959 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in CommunityToolkit.Diagnostics.dll |
| 2024-04-01 16:38:46.2781456 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Marketplace.Storefront.Telemetry.Contracts.dll |
| 2024-04-01 16:38:46.2937688 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Telemetry.dll |
| 2024-04-01 16:38:46.3093811 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Telemetry.Metadata.dll |
| 2024-04-01 16:38:46.3250110 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Win32.Primitives.dll |
| 2024-04-01 16:38:46.3406585 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in StoreDesktopExtension.exe |
| 2024-04-01 16:38:46.3406585 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in netstandard.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.AppContext.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Collections.Concurrent.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Collections.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Collections.NonGeneric.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Collections.Specialized.dll |
| 2024-04-01 16:38:46.3562703 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ComponentModel.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ComponentModel.EventBasedAsync.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ComponentModel.Primitives.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ComponentModel.TypeConverter.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Console.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.Contracts.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.Debug.dll |
| 2024-04-01 16:38:46.3719000 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Data.Common.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.FileVersionInfo.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.Process.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.StackTrace.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.TextWriterTraceListener.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.Tools.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.TraceSource.dll |
| 2024-04-01 16:38:46.3875069 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Diagnostics.Tracing.dll |
| 2024-04-01 16:38:46.4031290 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Drawing.Primitives.dll |
| 2024-04-01 16:38:46.4031290 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Dynamic.Runtime.dll |
| 2024-04-01 16:38:46.4031290 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Globalization.Calendars.dll |
| 2024-04-01 16:38:46.4031290 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Globalization.dll |
| 2024-04-01 16:38:46.4031290 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Globalization.Extensions.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.Compression.ZipFile.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.FileSystem.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.FileSystem.DriveInfo.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.FileSystem.Primitives.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.FileSystem.Watcher.dll |
| 2024-04-01 16:38:46.4187551 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.Compression.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.IsolatedStorage.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.MemoryMappedFiles.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.Pipes.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.IO.UnmanagedMemoryStream.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Linq.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Linq.Expressions.dll |
| 2024-04-01 16:38:46.4343825 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Linq.Parallel.dll |
| 2024-04-01 16:38:46.4500283 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Linq.Queryable.dll |
| 2024-04-01 16:38:46.4500283 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.NameResolution.dll |
| 2024-04-01 16:38:46.4500283 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.NetworkInformation.dll |
| 2024-04-01 16:38:46.4500283 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Ping.dll |
| 2024-04-01 16:38:46.4500283 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Http.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Primitives.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Requests.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Security.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.WebHeaderCollection.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.Sockets.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.WebSockets.Client.dll |
| 2024-04-01 16:38:46.4656361 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Net.WebSockets.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ObjectModel.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Reflection.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Reflection.Extensions.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Reflection.Primitives.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Resources.Reader.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Resources.ResourceManager.dll |
| 2024-04-01 16:38:46.4817309 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Resources.Writer.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.CompilerServices.VisualC.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Extensions.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Handles.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.InteropServices.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Numerics.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Serialization.Formatters.dll |
| 2024-04-01 16:38:46.4969112 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.InteropServices.RuntimeInformation.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Serialization.Json.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Claims.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Serialization.Xml.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Runtime.Serialization.Primitives.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Cryptography.Algorithms.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Cryptography.Csp.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Cryptography.Encoding.dll |
| 2024-04-01 16:38:46.5125603 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Cryptography.Primitives.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Cryptography.X509Certificates.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.Principal.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Security.SecureString.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Text.Encoding.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Text.Encoding.Extensions.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Text.RegularExpressions.dll |
| 2024-04-01 16:38:46.5281405 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.dll |
| 2024-04-01 16:38:46.5437678 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.Overlapped.dll |
| 2024-04-01 16:38:46.5437678 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.Tasks.dll |
| 2024-04-01 16:38:46.5437678 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.Tasks.Parallel.dll |
| 2024-04-01 16:38:46.5437678 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.Thread.dll |
| 2024-04-01 16:38:46.5437678 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.ThreadPool.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Threading.Timer.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.ReaderWriter.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.XDocument.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.XmlDocument.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.XmlSerializer.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.XPath.dll |
| 2024-04-01 16:38:46.5594134 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.ValueTuple.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in System.Xml.XPath.XDocument.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.Interop.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.Polyfills.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.Services.Abstractions.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.Services.dll |
| 2024-04-01 16:38:46.5750101 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WinStore.Instrumentation.dll |
| 2024-04-01 16:41:35.0032798 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in mspaint.exe |
| 2024-04-01 16:41:35.0503313 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in PaintUI.dll |
| 2024-04-01 16:42:38.2257227 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Microsoft.Windows.Widgets.dll |
| 2024-04-01 16:42:45.9135425 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WebView2Loader.dll |
| 2024-04-01 16:42:45.9292307 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WidgetPicker.dll |
| 2024-04-01 16:42:46.1479297 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in Widgets.exe |
| 2024-04-01 16:42:46.1792429 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in WidgetService.exe |
| 2024-04-01 16:42:46.1792429 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in wv2winrt.dll |
| 2024-04-01 16:42:46.8510636 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in GamePassWidget.exe |
| 2024-04-01 16:42:46.8510636 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in GamePassWidgetAppService.dll |
| 2024-04-01 16:43:19.0249302 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in olk.exe |
| 2024-04-01 16:43:19.0717827 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in xpdAgent.exe |
| 2024-04-01 16:43:19.0874202 | **Chronos** | TIMESTOMP_BACKDATE (Score: 80) in xpdAPI.dll |

## 3. 高優先度検知詳細


---
*End of SkiaHelios Report.*