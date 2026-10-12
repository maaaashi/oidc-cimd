# OIDC × Client ID Metadata Document (CIMD) × Resource Indicators デモ

[OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) を手元で試すための最小構成です。
**client_id が「クライアントのメタデータ JSON の URL」になり、OP への事前登録が不要になる** 仕組みを体験できます。
さらに [Resource Indicators (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707) で、**アクセストークンの `aud` を API ごとに絞る** 動きも確認できます。
[Protected Resource Metadata (RFC 9728)](https://www.rfc-editor.org/rfc/rfc9728) と組み合わせた **MCP の認可フロー** も試せます。
[DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449) で、**トークンをクライアントの鍵に紐付け、盗まれても使えなくする** 動きも確認できます。
[PAR (RFC 9126)](https://www.rfc-editor.org/rfc/rfc9126) で、**認可リクエストをブラウザの URL に載せず、OP に直接送る** 動きも確認できます。

## 起動

```bash
docker compose up -d
docker compose logs -f   # OP がメタデータを取得する様子が見える
```

1. http://localhost:4000 を開く (クライアント / RP)
2. 「OP でログイン」 → OP の同意画面 (alice / password が入力済み)
3. 「許可」 → ID トークンと、API 呼び分けの結果 (①〜⑥)、DPoP の攻撃パターン (⑦〜⑩) が表示される

停止: `docker compose down`

## 構成

| サービス | URL | 役割 |
|---|---|---|
| client | http://localhost:4000 | RP。`/client-metadata.json` で自分のメタデータを公開 |
| op | http://localhost:3000 | CIMD / RFC 8707 対応の OpenID Provider (自作・依存なし) |
| api-a | http://localhost:5000 | リソースサーバー兼 MCP サーバー (`/mcp`)。`aud` に `http://localhost:5000` を含むトークンだけ受け付ける |
| api-b | http://localhost:5001 | 同上 (`http://localhost:5001`) |

いずれも依存パッケージなしの Node.js で、`start.js` が 1 つのコンテナ内で 4 プロセスとして起動します。
DPoP proof の検証は OP と API で共通なので `lib/dpop.js` にまとめています。

## 流れ

```
Client ──(0) POST /par (client_id=http://localhost:4000/client-metadata.json, redirect_uri, scope, resource, PKCE ...)──▶ OP
       ◀── request_uri  (PAR, 後述)
Browser ──(1) /authorize?client_id=...&request_uri=...──▶ OP
OP ──(2) GET http://localhost:4000/client-metadata.json──▶ Client   ※ 実際は (0) の時点で取得
OP: (3) 検証 → 同意画面に client_name / logo_uri / ドメインを表示
Browser ──(4) code──▶ Client ──(5) /token (client_id + PKCE, シークレット無し)──▶ OP
```

OP が行う主なチェック (`op/server.js` の `getClientMetadata`):

- client_id URL は https・パス必須・フラグメント/認証情報/dot segment 禁止
- ドキュメント内の `client_id` が取得元 URL と **完全一致**
- `client_secret` を含まない、`token_endpoint_auth_method` が `client_secret_*` でない
- `redirect_uri` はドキュメントの `redirect_uris` と完全一致
- サイズ上限 (5KB)、リダイレクト不可、タイムアウト、`Cache-Control: max-age` に従ってキャッシュ

OP は discovery で `client_id_metadata_document_supported: true` を公開しています。

## Resource Indicators (RFC 8707)

```
/authorize ?resource=http://localhost:5000&resource=http://localhost:5001   ← 両 API への同意を取る
/token (code)          resource=http://localhost:5000  → AT(aud=5000) + refresh_token
/token (refresh_token) resource=http://localhost:5001  → AT(aud=5001)
```

ログイン後の画面で以下を確認できます。

| # | 内容 | 結果 |
|---|---|---|
| ① | 認可コード交換で `resource=API A` | `aud=http://localhost:5000` の AT |
| ② | リフレッシュで `resource=API B` | `aud=http://localhost:5001` の AT |
| ③ | API A を A 用トークンで呼ぶ | 200 |
| ④ | API B を A 用トークンで呼ぶ | **401** (audience 不一致) |
| ⑤ | API B を B 用トークンで呼ぶ | 200 |
| ⑥ | 同意していない `resource=http://localhost:5002` を要求 | **400 invalid_target** |

ポイント:

- OP は `resource` を絶対 URI・フラグメント無し・既知の API (`RESOURCES` 環境変数) で検証し、だめなら `invalid_target`
- トークンリクエストの `resource` は、認可時に同意した範囲の部分集合のみ許可
- アクセストークンは RFC 9068 形式の JWT (`typ: at+jwt`)。API は署名・`iss`・`exp` に加え **`aud` が自分か** を検証する
- 1 つの API 用のトークンが漏れても他の API では使えない (トークンの使い回し防止)

## DPoP (RFC 9449)

OIDC フローのトークンリクエストと API 呼び出しには、すべて DPoP proof を付けています。

```
Client: 起動時に ES256 の鍵ペアを生成 (OP への登録は不要)
Client ──/token  DPoP: <proof(htm=POST, htu=/token, jwk=公開鍵)>──▶ OP
       ◀── token_type: DPoP, AT に cnf.jkt (= 公開鍵の thumbprint)。リフレッシュトークンも同じ鍵に紐付け
Client ──GET /api/data  Authorization: DPoP <AT>
                        DPoP: <proof(htm=GET, htu=/api/data, ath=hash(AT))>──▶ API
API: proof の署名 → thumbprint が cnf.jkt と一致? → htm/htu/ath/iat → jti 未使用? → 200
```

| # | 攻撃 | 結果 |
|---|---|---|
| ⑦ | 盗んだ AT を `Authorization: Bearer` で送る | **401** (DPoP に紐付いたトークンは Bearer では使えない) |
| ⑧ | 盗んだ AT に攻撃者自身の鍵の proof を付ける | **401 invalid_dpop_proof** (鍵が `cnf.jkt` と不一致) |
| ⑨ | ③ の proof をそのまま再送 | **401 invalid_dpop_proof** (`jti` の再利用) |
| ⑩ | 盗んだリフレッシュトークンを攻撃者の鍵で使う | **400 invalid_grant** |

ポイント:

- `aud` (RFC 8707) は「**どの API で**」使えるかを絞り、DPoP は「**誰が**」使えるかを絞る。両方で漏えい時の被害を小さくできる
- シークレットを持てない公開クライアント (CIMD のクライアントなど) でも、その場で作った鍵だけで使える
- OP は discovery に `dpop_signing_alg_values_supported`、API は PRM に `dpop_bound_access_tokens_required: false` を公開
- CIMD のメタデータに `"dpop_bound_access_tokens": true` を書くと、OP はそのクライアントの DPoP 無しトークンリクエストを拒否する (このデモのクライアントは MCP フローで Bearer を使うので書いていない)
- MCP 風フローは Bearer のまま (MCP の認可仕様が `Authorization: Bearer` を前提としているため)

## MCP 風フロー (RFC 9728 + RFC 8414 + CIMD)

トップページの「MCP 風フロー」から、[MCP の認可仕様](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) と同じ手順を試せます。
クライアントは **MCP サーバーの URL (`http://localhost:5000/mcp`) しか知らない** 状態から始まります。

```
Client ──(1) POST /mcp (トークン無し)──▶ MCP サーバー
       ◀── 401 WWW-Authenticate: Bearer resource_metadata="http://localhost:5000/.well-known/oauth-protected-resource", scope="mcp:tools"
Client ──(2) GET /.well-known/oauth-protected-resource──▶ MCP サーバー      (RFC 9728)
       ◀── { resource: "http://localhost:5000", authorization_servers: ["http://localhost:3000"], scopes_supported: ["mcp:tools"] }
Client ──(3) GET /.well-known/oauth-authorization-server──▶ OP             (RFC 8414)
       ◀── { ..., client_id_metadata_document_supported: true }
Client ──(4) /authorize?client_id=<メタデータURL>&resource=http://localhost:5000&scope=mcp:tools  (CIMD + PKCE + RFC 8707)
Client ──(5) /token resource=http://localhost:5000 → AT(aud=5000, scope=mcp:tools)
Client ──(6) POST /mcp initialize / tools/list / tools/call (Bearer AT) → 200
Client ──(7) 同じ AT で http://localhost:5001/mcp → 401 (audience 不一致)
```

ポイント:

- 認可サーバー・`resource`・`scope` はすべて **401 レスポンスから芋づる式に発見** する。事前に設定するのは MCP サーバーの URL だけ
- OP への事前登録も不要 (CIMD)。MCP クライアントは「どの認可サーバーに当たるか事前に分からない」ので、CIMD と特に相性がよい
- クライアントは PRM の `resource` が接続先 MCP サーバーを指しているか、AS メタデータの `issuer` が PRM の値と一致するかを検証する
- MCP は OIDC ではなく OAuth なので `scope=mcp:tools` だけを要求し、ID トークンは発行されない
- `mcp:tools` を持たないトークン (OIDC フローで取ったもの) で `/mcp` を呼ぶと `403 insufficient_scope`
- 別の MCP サーバー用のトークンは `aud` で拒否される (MCP 仕様が禁止している「トークンのパススルー」を防ぐ)

## PAR (RFC 9126)

通常ログインと MCP 風フローは、認可リクエストを PAR で送っています。

```
Client ──POST /par  client_id, redirect_uri, scope, resource, state, nonce, code_challenge ...
                    DPoP: <proof(htm=POST, htu=/par)>──▶ OP
       ◀── 201 { request_uri: "urn:ietf:params:oauth:request_uri:...", expires_in: 60 }
Browser ──GET /authorize?client_id=<メタデータURL>&request_uri=urn:...──▶ OP   ← URL に載るのはこの 2 つだけ
```

- OP は `/par` で、`/authorize` と同じ検証 (CIMD メタデータ・redirect_uri・scope・PKCE・resource) を行う。エラーはブラウザを経由せず、JSON で直接クライアントに返る
- `/authorize` では `request_uri` が指す中身 **だけ** を使い、URL に付いた他のパラメーターは無視する (改ざん防止)
- `request_uri` は 60 秒で失効し、1 回しか使えない。PAR を送ったクライアントの client_id とセットでないと使えない
- CIMD のメタデータに `"require_pushed_authorization_requests": true` を書いているので、OP はこのクライアントの PAR 無しの認可リクエストを `invalid_request` で拒否する
- PAR に DPoP proof を付けると、OP はその鍵の thumbprint (`dpop_jkt`) を認可コードに紐付ける (RFC 9449 §10)。コードは同じ鍵の proof を付けたトークンリクエストでしか交換できない
- OP は discovery で `pushed_authorization_request_endpoint` と `require_pushed_authorization_requests: false` (OP 全体では任意) を公開。MCP 風フローのクライアントは、AS メタデータにこれがあれば PAR を使う

トップページの「PAR の動きを試す」:

| 操作 | 結果 |
|---|---|
| PAR を使わず URL で送る | URL に全パラメーターが並ぶ。**`error=invalid_request`** (このクライアントは PAR 必須) |
| PAR の後、URL に `scope` / `resource` / `redirect_uri` を書き足す | **無視される**。同意画面に表示され、トークンは PAR で送った内容どおり |
| `request_uri` を先に他者が使う | **OP のエラー画面** (使い捨て) |
| `request_uri` を別の client_id と組み合わせる | **OP のエラー画面** (クライアントに紐付いている) |

## 失敗パターン

トップページの「失敗パターンを試す」から、OP がどう弾くかを確認できます。
最初の 4 つは、OP の画面でのエラー表示を見るため、あえて PAR を使わずに URL で送っています。

- メタデータに無い redirect_uri
- ドキュメント内 client_id と URL の不一致
- ドキュメントが 404
- パスの無い client_id URL
- OP が知らない resource を要求 (PAR で送るので、`invalid_target` が JSON で直接クライアントに返る)

http://localhost:3000 では OP がキャッシュしているメタデータを確認できます。

## 注意 (デモ用の簡略化)

- 仕様上 client_id URL は **https 必須** です。ローカルで試すため、OP は `ALLOW_HTTP_LOCALHOST_CLIENT_ID=true` のときだけ `http://localhost` を許可しています。
- ブラウザと各プロセスから同じ `localhost:<port>` に届くよう、全プロセスを 1 コンテナで動かしています。
- リフレッシュトークンはローテーションしますが、再利用検知などはしていません。
- DPoP の `DPoP-Nonce` (サーバー提供の nonce) は実装していません。使用済み `jti` と PAR の `request_uri` はプロセスごとのメモリに保持しています。
- PAR のリクエストオブジェクト (JAR, RFC 9101 の署名付き `request`) には対応していません。
- MCP サーバーは JSON-RPC を JSON で返すだけの最小実装です (SSE・セッション管理なし)。PRM の `resource` は MCP エンドポイントの親 (`http://localhost:5000`) にしており、クライアントはパスの前方一致で検証しています。
- 本番では SSRF 対策 (内部 IP への取得禁止など)、`private_key_jwt` 対応、署名鍵の永続化なども必要です。
