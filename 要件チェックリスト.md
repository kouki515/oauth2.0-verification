# RFC6749 認可サーバー実装要件チェックリスト

## 1. エンドポイント要件

### MUST要件
- [ ] 認可エンドポイントはTLSを使用する (Section 3.1)
- [ ] トークンエンドポイントはTLSを使用する (Section 3.2)
- [ ] エンドポイントは絶対URIである (Section 3.1/3.2)

### SHOULD要件
- [ ] 認可エンドポイントはHTTP GETをサポート (Section 3.1)
- [ ] トークンエンドポイントはHTTP POSTをサポート (Section 3.2)

## 2. 認可レスポンス処理

### MUST要件
- [ ] 認可コードは一時的かつ単一使用である (Section 4.1.2)
- [ ] スコープの検証を実施 (Section 3.3)
- [ ] リクエストに含まれるresponse_typeを検証 (Section 4.1.1)
- [ ] リダイレクトURIの妥当性を検証 (Section 3.1.2)

### SHOULD要件
- [ ] 認可コードの有効期限を10分以内に設定 (Section 4.1.2)
- [ ] 認可要求の状態をセッションに保存 (Section 4.1.1)

## 3. トークン発行

### MUST要件
- [ ] アクセストークンは一意である (Section 5)
- [ ] トークンレスポンスにトークンタイプを含める (Section 5.1)
- [ ] アクセストークンのスコープを検証・制限 (Section 3.3)
- [ ] Bearer以外のトークンタイプを使用する場合は仕様に準拠 (Section 5.1)

### SHOULD要件
- [ ] アクセストークンに有効期限を設定 (Section 5.1)
- [ ] expires_inパラメータを含める (Section 5.1)

## 4. エラーハンドリング

### MUST要件
- [ ] 認可エラーは規定のエラーコードを使用 (Section 4.1.2.1)
    - invalid_request
    - unauthorized_client
    - access_denied
    - unsupported_response_type
    - invalid_scope
    - server_error
    - temporarily_unavailable
- [ ] トークンエラーは規定のエラーコードを使用 (Section 5.2)
- [ ] エラーレスポンスはJSONフォーマット (Section 5.2)

### SHOULD要件
- [ ] エラーの説明文を提供 (Section 5.2)
- [ ] エラーの詳細情報のURIを提供 (Section 5.2)

## 5. セキュリティ対策

### MUST要件
- [ ] stateパラメータの値を検証 (Section 10.12)
- [ ] アクセストークンの漏洩対策を実装 (Section 10.3)
- [ ] リプレイ攻撃対策を実装 (Section 10.12)
- [ ] 認可コードの再利用を防止 (Section 4.1.2)

### SHOULD要件
- [ ] アクセストークンの有効期限を制限 (Section 10.4)
- [ ] TLS証明書の検証を実施 (Section 10.9)
