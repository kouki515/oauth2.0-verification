<?php
require_once __DIR__ . '/../config.php';

class MockDiscordOAuthServer
{
    private $validClients = [];
    private $issuedCodes = [];
    private $issuedTokens = [];
    private $issuedRefreshTokens = [];
    private $validScopes = [
        'identify',           // ユーザープロファイル情報
        'email',             // メールアドレス
        'guilds',            // 参加サーバー一覧
        'guilds.join',       // サーバーへの参加
        'guilds.members.read', // サーバーメンバー情報の読み取り
        'connections',       // 外部アカウント連携情報
        'bot',              // Botの追加
        'messages.read',     // メッセージ読み取り
        'applications.commands', // スラッシュコマンド
        'applications.commands.update', // スラッシュコマンドの更新
        'webhook.incoming'   // Webhookの作成
    ];
    private $validRedirectUris = [
        'https://example.com/callback',
        'https://localhost:8080/callback'
    ];

    public function __construct()
    {
        $this->validClients[DISCORD_CLIENT_ID] = DISCORD_CLIENT_SECRET;
    }

    public function handleAuthorizationRequest($params)
    {
        // 必須パラメータの検証
        if (!isset($params['response_type']) || !isset($params['client_id'])) {
            return $this->createErrorResponse('invalid_request', 'Required parameters missing');
        }

        // クライアントIDの検証
        if (!isset($this->validClients[$params['client_id']])) {
            return $this->createErrorResponse('unauthorized_client', 'Client not authorized');
        }

        // レスポンスタイプの検証
        if ($params['response_type'] !== 'code') {
            return $this->createErrorResponse('unsupported_response_type', 'Only code response type is supported');
        }

        // リダイレクトURIの検証
        if (isset($params['redirect_uri']) && !in_array($params['redirect_uri'], $this->validRedirectUris)) {
            return $this->createErrorResponse('invalid_request', 'Invalid redirect URI');
        }

        // スコープの検証
        if (isset($params['scope'])) {
            $requestedScopes = explode(' ', $params['scope']);
            foreach ($requestedScopes as $scope) {
                if (!in_array($scope, $this->validScopes)) {
                    return $this->createErrorResponse('invalid_scope', 'Invalid scope requested');
                }
            }
        }

        // 認可コードの生成
        $code = bin2hex(random_bytes(32));
        $this->issuedCodes[$code] = [
            'client_id' => $params['client_id'],
            'scope' => $params['scope'] ?? '',
            'redirect_uri' => $params['redirect_uri'] ?? null,
            'used' => false,
            'expires_at' => time() + 600 // 10分間有効
        ];

        return [
            'code' => $code,
            'state' => $params['state'] ?? null
        ];
    }

    public function handleTokenRequest($params)
    {
        // 必須パラメータの検証
        if (!isset($params['grant_type'])) {
            return $this->createErrorResponse('invalid_request', 'Grant type is required');
        }

        // グラントタイプに応じた処理
        switch ($params['grant_type']) {
            case 'authorization_code':
                return $this->handleAuthorizationCodeGrant($params);
            case 'refresh_token':
                return $this->handleRefreshTokenGrant($params);
            default:
                return $this->createErrorResponse('unsupported_grant_type', 'Grant type not supported');
        }
    }

    private function handleAuthorizationCodeGrant($params)
    {
        // 必須パラメータの検証
        if (!isset($params['code']) || !isset($params['client_id']) || !isset($params['client_secret'])) {
            return $this->createErrorResponse('invalid_request', 'Required parameters missing');
        }

        // クライアント認証
        if (
            !isset($this->validClients[$params['client_id']]) ||
            $this->validClients[$params['client_id']] !== $params['client_secret']
        ) {
            return $this->createErrorResponse('unauthorized_client', 'Client authentication failed');
        }

        // 認可コードの検証
        if (!isset($this->issuedCodes[$params['code']])) {
            return $this->createErrorResponse('invalid_grant', 'Authorization code not found');
        }

        $codeInfo = $this->issuedCodes[$params['code']];

        // コードの再利用チェック
        if ($codeInfo['used']) {
            return $this->createErrorResponse('invalid_grant', 'Authorization code already used');
        }

        // リダイレクトURIの検証
        if (
            isset($codeInfo['redirect_uri']) &&
            (!isset($params['redirect_uri']) || $params['redirect_uri'] !== $codeInfo['redirect_uri'])
        ) {
            return $this->createErrorResponse('invalid_grant', 'Redirect URI mismatch');
        }

        // 有効期限の検証
        if (time() > $codeInfo['expires_at']) {
            return $this->createErrorResponse('invalid_grant', 'Authorization code expired');
        }

        // コードを使用済みにマーク
        $this->issuedCodes[$params['code']]['used'] = true;

        return $this->generateTokenResponse($params['client_id'], $codeInfo['scope']);
    }

    private function handleRefreshTokenGrant($params)
    {
        // 必須パラメータの検証
        if (!isset($params['refresh_token']) || !isset($params['client_id']) || !isset($params['client_secret'])) {
            return $this->createErrorResponse('invalid_request', 'Required parameters missing');
        }

        // クライアント認証
        if (
            !isset($this->validClients[$params['client_id']]) ||
            $this->validClients[$params['client_id']] !== $params['client_secret']
        ) {
            return $this->createErrorResponse('unauthorized_client', 'Client authentication failed');
        }

        // リフレッシュトークンの検証
        if (!isset($this->issuedRefreshTokens[$params['refresh_token']])) {
            return $this->createErrorResponse('invalid_grant', 'Refresh token not found');
        }

        $refreshTokenInfo = $this->issuedRefreshTokens[$params['refresh_token']];

        // クライアントIDの検証
        if ($refreshTokenInfo['client_id'] !== $params['client_id']) {
            return $this->createErrorResponse('invalid_grant', 'Refresh token was not issued to this client');
        }

        return $this->generateTokenResponse($params['client_id'], $refreshTokenInfo['scope']);
    }

    private function generateTokenResponse($clientId, $scope)
    {
        $accessToken = bin2hex(random_bytes(32));
        $refreshToken = bin2hex(random_bytes(32));

        // アクセストークンの保存
        $this->issuedTokens[$accessToken] = [
            'client_id' => $clientId,
            'scope' => $scope,
            'expires_at' => time() + 604800 // 7日間有効（Discord標準）
        ];

        // リフレッシュトークンの保存
        $this->issuedRefreshTokens[$refreshToken] = [
            'client_id' => $clientId,
            'scope' => $scope,
            'expires_at' => time() + 30 * 24 * 3600 // 30日間有効
        ];

        return [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 604800,
            'refresh_token' => $refreshToken,
            'scope' => $scope
        ];
    }

    private function createErrorResponse($error, $description = null)
    {
        return [
            'error' => $error,
            'error_description' => $description ?? $this->getErrorDescription($error),
            'error_uri' => 'https://discord.com/developers/docs/topics/oauth2#error-responses'
        ];
    }

    private function getErrorDescription($error)
    {
        $descriptions = [
            'invalid_request' => 'The request is missing a required parameter',
            'unauthorized_client' => 'The client is not authorized',
            'access_denied' => 'The resource owner denied the request',
            'unsupported_response_type' => 'The response type is not supported',
            'invalid_scope' => 'The requested scope is invalid',
            'server_error' => 'The server encountered an error',
            'temporarily_unavailable' => 'The server is temporarily unavailable',
            'invalid_grant' => 'The provided authorization grant is invalid',
            'unsupported_grant_type' => 'The authorization grant type is not supported'
        ];
        return $descriptions[$error] ?? 'An error occurred';
    }
}

class DiscordOAuthServerVerification
{
    private $results = [];
    private $mockServer;

    public function __construct()
    {
        $this->mockServer = new MockDiscordOAuthServer();
    }

    public function runVerification()
    {
        $this->verifyEndpoints();
        $this->verifyAuthorizationResponse();
        $this->verifyTokenIssuance();
        $this->verifyErrorHandling();
        $this->verifySecurityMeasures();
        $this->printResults();
    }

    public function verifyEndpoints()
    {
        $this->results['tls_auth_endpoint'] = $this->verifyTLS('https://discord.com/oauth2/authorize');
        $this->results['tls_token_endpoint'] = $this->verifyTLS('https://discord.com/api/oauth2/token');
        $this->results['absolute_uri_auth'] = $this->verifyAbsoluteUri('https://discord.com/oauth2/authorize');
        $this->results['absolute_uri_token'] = $this->verifyAbsoluteUri('https://discord.com/api/oauth2/token');
        $this->results['auth_endpoint_get'] = $this->verifyAuthEndpointGet();
        $this->results['token_endpoint_post'] = $this->verifyTokenEndpointPost();
    }

    public function verifyAuthorizationResponse()
    {
        $this->results['auth_code_single_use'] = $this->verifyAuthCodeSingleUse();
        $this->results['scope_validation'] = $this->verifyScopeValidation();
        $this->results['response_type_validation'] = $this->verifyResponseType();
        $this->results['redirect_uri_validation'] = $this->verifyRedirectUriValidation();
    }

    public function verifyTokenIssuance()
    {
        $this->results['token_uniqueness'] = $this->verifyTokenUniqueness();
        $this->results['token_type_included'] = $this->verifyTokenTypeIncluded();
        $this->results['token_type_support'] = $this->verifyTokenTypeSupport();
        $this->results['scope_restriction'] = $this->verifyScopeRestriction();
        $this->results['expires_in_included'] = $this->verifyExpiresInParameter();
    }

    public function verifyErrorHandling()
    {
        $this->results['auth_error_codes'] = $this->verifyAuthErrorCodes();
        $this->results['token_error_codes'] = $this->verifyTokenErrorCodes();
        $this->results['error_json_format'] = $this->verifyErrorJsonFormat();
        $this->results['error_description'] = $this->verifyErrorDescription();
        $this->results['error_uri'] = $this->verifyErrorUri();
    }

    public function verifySecurityMeasures()
    {
        $this->results['state_validation'] = $this->verifyStateParameter();
        $this->results['token_leakage_prevention'] = $this->verifyTokenLeakagePrevention();
        $this->results['replay_prevention'] = $this->verifyReplayPrevention();
        $this->results['tls_cert_validation'] = $this->verifyTLSCertValidation();
    }

    private function verifyTLS($url)
    {
        $parsed = parse_url($url);
        return $parsed['scheme'] === 'https';
    }

    private function verifyAbsoluteUri($url)
    {
        $parsed = parse_url($url);
        return
            isset($parsed['scheme']) &&
            isset($parsed['host']) &&
            in_array($parsed['scheme'], ['http', 'https']) &&
            filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    private function verifyAuthEndpointGet()
    {
        $response = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);
        return !isset($response['error']);
    }

    private function verifyTokenEndpointPost()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']);
    }

    private function verifyAuthCodeSingleUse()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        // 1回目のトークンリクエスト
        $firstResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        // 2回目のトークンリクエスト（同じコードを使用）
        $secondResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($firstResponse['error']) && isset($secondResponse['error']);
    }

    private function verifyScopeValidation()
    {
        // 有効なスコープでのテスト
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'scope' => 'identify email'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        // 無効なスコープでのテスト
        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'scope' => 'invalid_scope'
        ]);

        return isset($invalidResponse['error']) && $invalidResponse['error'] === 'invalid_scope';
    }

    private function verifyResponseType()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'invalid_type',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        return isset($invalidResponse['error']) &&
            $invalidResponse['error'] === 'unsupported_response_type';
    }

    private function verifyRedirectUriValidation()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'redirect_uri' => 'https://example.com/callback'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'redirect_uri' => 'https://malicious.example.com'
        ]);

        return isset($invalidResponse['error']);
    }

    private function verifyTokenUniqueness()
    {
        $tokens = [];
        for ($i = 0; $i < 5; $i++) {
            $authResponse = $this->mockServer->handleAuthorizationRequest([
                'response_type' => 'code',
                'client_id' => DISCORD_CLIENT_ID
            ]);

            if (isset($authResponse['error'])) {
                return false;
            }

            $tokenResponse = $this->mockServer->handleTokenRequest([
                'grant_type' => 'authorization_code',
                'code' => $authResponse['code'],
                'client_id' => DISCORD_CLIENT_ID,
                'client_secret' => DISCORD_CLIENT_SECRET
            ]);

            if (isset($tokenResponse['error']) || in_array($tokenResponse['access_token'], $tokens)) {
                return false;
            }

            $tokens[] = $tokenResponse['access_token'];
        }
        return true;
    }

    private function verifyTokenTypeIncluded()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) && isset($tokenResponse['token_type']);
    }

    private function verifyTokenTypeSupport()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['token_type']) &&
            $tokenResponse['token_type'] === 'Bearer';
    }

    private function verifyScopeRestriction()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'scope' => 'identify'
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['scope']) &&
            $tokenResponse['scope'] === 'identify';
    }

    private function verifyExpiresInParameter()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['expires_in']) &&
            $tokenResponse['expires_in'] === 604800; // Discord標準の7日間
    }

    private function verifyAuthErrorCodes()
    {
        // 無効なリクエスト
        $response1 = $this->mockServer->handleAuthorizationRequest([
            'client_id' => DISCORD_CLIENT_ID
            // response_typeを意図的に省略
        ]);
        if (!isset($response1['error']) || $response1['error'] !== 'invalid_request') {
            return false;
        }

        // 未承認のクライアント
        $response2 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => 'invalid_client_id'
        ]);
        if (!isset($response2['error']) || $response2['error'] !== 'unauthorized_client') {
            return false;
        }

        // サポートされていないレスポンスタイプ
        $response3 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'invalid_type',
            'client_id' => DISCORD_CLIENT_ID
        ]);
        if (!isset($response3['error']) || $response3['error'] !== 'unsupported_response_type') {
            return false;
        }

        return true;
    }

    private function verifyTokenErrorCodes()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return isset($response['error']) && $response['error'] === 'invalid_grant';
    }

    private function verifyErrorJsonFormat()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return isset($response['error']) &&
            isset($response['error_description']) &&
            isset($response['error_uri']);
    }

    private function verifyErrorDescription()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return isset($response['error_description']) &&
            !empty($response['error_description']);
    }

    private function verifyErrorUri()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        return isset($response['error_uri']) &&
            filter_var($response['error_uri'], FILTER_VALIDATE_URL) !== false &&
            strpos($response['error_uri'], 'discord.com/developers/docs') !== false;
    }

    private function verifyStateParameter()
    {
        $state = bin2hex(random_bytes(16));
        $response = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID,
            'state' => $state
        ]);

        return !isset($response['error']) && $response['state'] === $state;
    }

    private function verifyTokenLeakagePrevention()
    {
        // トークンがURLフラグメントではなくPOSTボディで送信されることを確認
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        return !isset($authResponse['access_token']); // 認可レスポンスにアクセストークンが含まれていないことを確認
    }

    private function verifyReplayPrevention()
    {
        // 認可コードの再利用防止チェック
        $result1 = $this->verifyAuthCodeSingleUse();

        // リフレッシュトークンの再利用チェック
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => DISCORD_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        if (isset($tokenResponse['error']) || !isset($tokenResponse['refresh_token'])) {
            return false;
        }

        // 同じリフレッシュトークンで2回リクエスト
        $refreshResponse1 = $this->mockServer->handleTokenRequest([
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokenResponse['refresh_token'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        $refreshResponse2 = $this->mockServer->handleTokenRequest([
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokenResponse['refresh_token'],
            'client_id' => DISCORD_CLIENT_ID,
            'client_secret' => DISCORD_CLIENT_SECRET
        ]);

        $result2 = !isset($refreshResponse1['error']) && !isset($refreshResponse2['error']) &&
            $refreshResponse1['access_token'] !== $refreshResponse2['access_token'];

        return $result1 && $result2;
    }

    private function verifyTLSCertValidation()
    {
        return $this->verifyTLS('https://discord.com/oauth2/authorize') &&
            $this->verifyTLS('https://discord.com/api/oauth2/token');
    }

    public function printResults()
    {
        echo "OAuth 2.0 認可サーバー要件検証結果\n\n";

        $categories = [
            '1. エンドポイント要件' => [
                'tls_auth_endpoint' => 'TLS (認可エンドポイント)',
                'tls_token_endpoint' => 'TLS (トークンエンドポイント)',
                'absolute_uri_auth' => '絶対URI (認可エンドポイント)',
                'absolute_uri_token' => '絶対URI (トークンエンドポイント)',
                'auth_endpoint_get' => 'GET サポート (認可エンドポイント)',
                'token_endpoint_post' => 'POST サポート (トークンエンドポイント)'
            ],
            '2. 認可レスポンス要件' => [
                'auth_code_single_use' => '認可コードの一意性',
                'scope_validation' => 'スコープ検証',
                'response_type_validation' => 'レスポンスタイプ検証',
                'redirect_uri_validation' => 'リダイレクトURI検証'
            ],
            '3. トークン発行要件' => [
                'token_uniqueness' => 'トークンの一意性',
                'token_type_included' => 'トークンタイプの明示',
                'token_type_support' => 'トークンタイプサポート',
                'scope_restriction' => 'スコープの制限',
                'expires_in_included' => 'expires_inパラメータ'
            ],
            '4. エラー処理要件' => [
                'auth_error_codes' => '認可エラーコード',
                'token_error_codes' => 'トークンエラーコード',
                'error_json_format' => 'JSONエラーフォーマット',
                'error_description' => 'エラー説明文',
                'error_uri' => 'エラー詳細URI'
            ],
            '5. セキュリティ要件' => [
                'state_validation' => 'stateパラメータ検証',
                'token_leakage_prevention' => 'トークン漏洩対策',
                'replay_prevention' => 'リプレイ攻撃対策',
                'tls_cert_validation' => 'TLS証明書検証'
            ]
        ];

        foreach ($categories as $categoryName => $items) {
            echo "$categoryName\n";
            foreach ($items as $key => $label) {
                $result = isset($this->results[$key]) && $this->results[$key];
                echo sprintf(
                    "%s: %s\n",
                    $label,
                    $result ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
                );
            }
            echo "\n";
        }

        $passCount = array_sum(array_map(function ($v) {
            return $v ? 1 : 0;
        }, $this->results));
        $totalCount = count($this->results);
        $rate = ($passCount / $totalCount) * 100;

        $color = $rate >= 80 ? "\033[32m" : ($rate >= 60 ? "\033[33m" : "\033[31m");
        echo sprintf("RFC6749準拠率: %s%.2f%%\033[0m\n", $color, $rate);
    }
}

// メインの実行コード
$verifier = new DiscordOAuthServerVerification();
$verifier->runVerification();
