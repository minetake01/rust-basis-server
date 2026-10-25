# Basis Server Rust 実装 — 互換性スライス

## 結論

Rust 実装 `rust-basis-server` は、既存 C# クライアントをそのまま接続させた状態で、
主要なワイヤ・対外挙動の互換性検証に成功しています。

- LiteNetLib 互換 UDP トランスポート（ConnectRequest/Accept、ReliableOrdered、
  Sequenced、Unreliable、Merged/CompactMerged、Ack、Ping/Pong、送信フラグメント）
- プロトコル 56（X25519 接続キー、ログイン transcript 署名、ChaCha20-Poly1305 の client→server 暗号化）
- Company/Product 検証、パスワード認証、DID Ed25519 チャレンジ応答
- サーバーメタデータ、RemotePlayer スポーンバッチ
- チャット中継、ボイス中継
- アバター High キーフレーム、追加データ、デルタ中継、アバターチェンジ中継
- 距離に応じた VeryLow / Low / Medium へのキーフレーム再パック
- 後入りクライアントへの最新キーフレーム入りスポーン
- 大きな join fill の raw Deflate 圧縮（`ServerReadyBatchMessage`）
- 初回起動時の C# 既定 `config.xml` 生成（`<exe>/config/config.xml`、schema v15）
- 旧 schema の `config.xml` に不足設定を追加し、C# と同じログを出すアップグレード
- ヘッドレス初回起動時の `NO ADMIN CONFIGURED` 警告ブロック
- 対話型の初回設定ウィザード（サーバー設定・管理者 UUID、スクリプト入力で E2E テスト済み）
- `BasisFirstAdmin` による permissions.xml への管理者シード
- 既存 `permissions.xml` の読み込み時に C# `EnsureDefaults` 相当で
  `default` / `moderator` / `admin` グループと `SeededDefaults` を補完。
  `admin` には `*` が入るため、管理者 UUID だけを書いたファイルでも
  ワールド／プロップのロード権限が有効になる。管理者シードも完全な
  グループ定義を書き出す。権限ファイルは `config.xml` と同じディレクトリから読む
- `config.xml` の主要フィールド、環境変数オーバーライド
- C# 同等のヘッダー・GET 限定 200/404/405・同時 32 リクエスト上限（503）を含む JSON ヘルスエンドポイント
- 未接続サーバー情報クエリ（raw と C# LiteNetLib クライアント経由の両方で確認済み。
  per-IP 500 ms と C# と同じ 100/s・burst 200 のグローバル制限付き）
- C# `basisctl` 制御ソケット（`status` / `players` / `help` / `shutdown` / `attach` ログストリーム）
- P2P シグナリング中継と offloaded pair 管理（NAT punch は未実装）
- 不正な接続データの `Rejected for reason: Invalid client data.` ログ
- `DisallowHeadless` による Headless クライアント拒否
- サーバー満員（kind 2）とプロトコル不一致（kind 1）の C# structured reject payload
- Company/Product 不一致時の C# 拒否理由
- 同一 DID の同時認証数制限（既定 2、超過時は拒否）
- 接続数に応じた認証タイムアウト（+12 ms/peer、最大 +45 秒、C# と同式）
- C# 形式のログ（`[HH:mm] [INFO|WARNING|ERROR]`、`Logs/yyyy-MM-dd.log`、起動・接続・切断・拒否イベント）
- 切断ピアの `DisconnectionChannel` ブロードキャスト
- Player cleanup と空サーバー時の NetworkID DB リセットログ
- モジュール単位の Cargo クレート分割（wire / crypto / protocol / avatar / config / logging / health / control / p2p / telemetry / permissions / setup / transport / server）
- 不正パスワードの接続前拒否

## 検証結果

```powershell
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\run-compat.ps1
```

実測出力（要旨）:

```text
PASS: wire/behavior compatibility checks succeeded
HarnessA: ... auth=True chat=compat-chat-b voice=6 avatarFrames=1 avatarPayload=159 spawn=1 delta=0 additional=0
HarnessB: ... auth=True chat=compat-chat-a voice=8 avatarFrames=2 avatarPayload=159 spawn=1 delta=1 additional=1
PASS: late joiner received the latest keyframe
PASS: wrong password was rejected
PASS: distance reduction produced VeryLow/Medium/High
ReductionB: ... avatarFrames=3 avatarPayload=159 spawn=1
```

ログ検証:

```powershell
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\check-log-compat.ps1
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\diff-log-compat.ps1
```

`diff-log-compat.ps1` は C# サーバーと Rust サーバーを同じ認証設定で起動し、同じ C# クライアント
ハーネスで接続・切断・不正パスワードを実行し、タイムスタンプを正規化して共通イベント列を
比較します。現状は **38 レコード一致**です。

`cargo test` は 100 件成功。実 Unity クライアントでサーバー配信 world の `Scene Load From Server Complete` を確認。Unity MCP 経由で Unity プロジェクトの正式ブートシーンを接続し、`test` world のロード、`Players=2` / `RemotePlayers=1` / `PlayerReady=True`、リモート位置の追従（Unity `(0.81, 5.49, -17.11)`、サーバー `(-0.101, 5.0800004, -18.227001)`）、エディタ発チャットの 56 コンソール到達、コンソール停止時の `Peer removed: 1` / `Player 1 removed and cleaned up.` と Unity の `RemotePlayers=0`、コンソール発チャットの Unity 受信 `[CHAT-IN] 2:headless-chat-0-21035`、ボイス受信キュー `BasisNetworkHandleVoice.Message.Count=1` を確認。`scripts/run-compat.ps1`（health version 56）、`scripts/check-log-compat.ps1`、`scripts/run-headless-56.ps1` は成功。特に `repack::tests::matches_the_csharp_repacker_oracle` は、
C# の `AvatarQualityRepacker` が同じ High 入力から生成した Medium/Low/VeryLow の
バイト列と Rust の出力が完全一致することを確認しています。

## 起動

```powershell
cargo build --release --manifest-path rust-basis-server\Cargo.toml -p basis-server
.\rust-basis-server\target\release\basis-server-rs.exe --port=4296
```

主なオプション:

```text
--port=4296
--bind=0.0.0.0
--password=...
--no-auth
--no-auth-identity
--config=config/config.xml
--no-avatar-reduction
--health-host=localhost
--health-port=10666
--health-path=/health
```

ヘルス例:

```powershell
Invoke-RestMethod http://127.0.0.1:10666/health
```

## 最適化と安全性

- ホットな 4 バイト Channeled ヘッダ、フラグメントヘッダ、3 バイト Ping ヘッダには
  `crates/basis-wire/src/fast.rs` の非アラインメント読み取りを使用。
- NetID 割当（channel 22）とミュート/タイピング/トークモードイベント（channel 38）の中継
- SceneDataMessage の受信・送信者 ID 付き中継（channel 24）
- AudioRecipients（channel 5 / 39 / 49 / 50 / 51）を保存し、ボイス中継先を送信者ごとの受信者リストで制御
- ヘッドレス 56 クライアント 2 台で認証・参加通知・アバター中継・ボイス中継・チャット送受信を確認（`[Fairness] 2 senders seen` / `[VOICE] delivered 100.00% ... streams=2` / `[CHAT] sender=...`）
- SceneDataMessage を送信者・messageIndex 単位でキャッシュし、後から参加したピアへ初期 scene 状態を再送（ヘッドレスで `[SCENE] sender=0 index=100` を受信）
- Ownership の取得・変更・削除（channel 19 / 20 / 21）と新規参加者への所有状態再送（`[OWNER] owner=1 id=...`）
- LoadResource / UnloadResource（channel 25 / 26）のキャッシュ・中継・新規参加者への再送（`[RESOURCE] id=...`）
- ヘッドレス切断後 5 秒で `Peer removed` / `broadcast departure` / `Player N removed and cleaned up.` を確認し、残存クライアント側でも `[DEPARTURE] id=...` を受信
- 実 `Basis Unity.exe`（プロトコル 56）を `--connection=127.0.0.1:4296#default_password` で接続し、認証・ローカルプレイヤー生成・NetID 解決（`BasisCameraDollyManager`）・他クライアントの参加通知まで確認。CLI 接続はメニューのワールドロードを省略するため、実プレイ確認はメニュー経由で行う必要がある。メニューから localhost:4296 へ接続し、アバターが描画されることを確認済み。
- `unsafe` は `basis-wire/src/fast.rs` に局所化。各関数に `# Safety` 契約、`debug_assert!`、
  安全な読み書きとの一致テストを用意。
- クレート全体で `#![deny(unsafe_op_in_unsafe_fn)]` を有効化。
- パケットパーサ本体は安全 Rust で、長さ検証を通過した後にのみ高速パスを呼ぶ。
- 距離削減は受信者の位置に応じてキーフレームを再パックし、帯域を削減。

## 現時点の制約

以下は未実装または部分実装です。フルパリティではありません。

- 低品質ピアへのデルタ再パック、送信間隔スケジューラ、LZ4/Zstd バンドル、
  キーフレーム／デルタの完全なリベースライン
- Resources、Scene、Ownership、NetworkID DB の本実装、画像キャッシュ、コンテンツ共有、
  PIP カメラ、モデレーション、権限の強制、ワードフィルタ、レート制限
- REST/管理 API、コンソール制御ソケット、systemd 統合、P2P ブローカー/NAT パンチ、
  GPU オフロード
- Reliable の完全な再送ウィンドウ／バックオフ。100 ms・最大 5 回の基本再送は実装済みだが、
  LiteNetLib の完全なウィンドウ制御と輻輳制御は未実装
- 低品質ピアはキーフレームのみ受信するため、アバター更新はキーフレーム周期
- テレメトリは Rust 実装自身の実測値。起動時は CPU 機能・コア数・RSS・空きメモリ・Peer の固定サイズ・
  削減／バンドル設定、30 秒ごとはループ周期と busy/待機時間、pkt/s、RSS、CPU、キューの深さ、
  reliable resend、bundle 数。C# の `[CPU/POP]` / `[BSR] Load` の数値文字列は再現しない
- ログ形式・主要イベントは一致するが、未実装サブシステムのログは完全一致しない

## ファイル

```text
rust-basis-server/
  README.md
  COMPATIBILITY-ja.md
  crates/basis-wire/
  crates/basis-protocol/
  crates/basis-avatar/
  crates/basis-config/
  crates/basis-logging/
  crates/basis-health/
  crates/basis-transport/
  bin/basis-server/
  scripts/run-compat.ps1
  scripts/check-log-compat.ps1
.basis-test/harness/   C# 互換性ハーネス
```
































































































