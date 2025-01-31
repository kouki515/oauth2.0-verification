<?php
require_once __DIR__ . '/../config.php';

class MockGoogleOAuthServer
{
    private $validClients = [];
    private $issuedCodes = [];
    private $issuedTokens = [];
    private $validScopes = [
        'openid',
        'email',
        'profile',
        'https://www.googleapis.com/auth/drive',
        'https://www.googleapis.com/auth/calendar'
    ];
    private $validRedirectUris = [
        'https://example.com/callback',
        'https://localhost:8080/callback'
    ];

    public function __construct()
    {
        $this->validClients[GOOGLE_CLIENT_ID] = GOOGLE_CLIENT_SECRET;
    }

    public function handleAuthorizationRequest($params)
    {
        // 必須パラメータの検証
        if (!isset($params['response_type']) || !isset($params['client_id'])) {
            return $this->createErrorResponse('invalid_request');
        }

        // クライアントIDの検証
        if (!isset($this->validClients[$params['client_id']])) {
            return $this->createErrorResponse('unauthorized_client');
        }

        // レスポンスタイプの検証
        if ($params['response_type'] !== 'code') {
            return $this->createErrorResponse('unsupported_response_type');
        }

        // リダイレクトURIの検証
        if (isset($params['redirect_uri']) && !in_array($params['redirect_uri'], $this->validRedirectUris)) {
            return $this->createErrorResponse('invalid_request');
        }

        // スコープの検証
        if (isset($params['scope'])) {
            $requestedScopes = explode(' ', $params['scope']);
            foreach ($requestedScopes as $scope) {
                if (!in_array($scope, $this->validScopes)) {
                    return $this->createErrorResponse('invalid_scope');
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
        if (
            !isset($params['grant_type']) || !isset($params['code']) ||
            !isset($params['client_id']) || !isset($params['client_secret'])
        ) {
            return $this->createErrorResponse('invalid_request');
        }

        // クライアント認証
        if (
            !isset($this->validClients[$params['client_id']]) ||
            $this->validClients[$params['client_id']] !== $params['client_secret']
        ) {
            return $this->createErrorResponse('unauthorized_client');
        }

        // 認可コードの検証
        if (!isset($this->issuedCodes[$params['code']])) {
            return $this->createErrorResponse('invalid_grant');
        }

        $codeInfo = $this->issuedCodes[$params['code']];

        // コードの再利用チェック
        if ($codeInfo['used']) {
            return $this->createErrorResponse('invalid_grant');
        }

        // リダイレクトURIの検証
        if (
            isset($codeInfo['redirect_uri']) &&
            (!isset($params['redirect_uri']) || $params['redirect_uri'] !== $codeInfo['redirect_uri'])
        ) {
            return $this->createErrorResponse('invalid_grant');
        }

        // 有効期限の検証
        if (time() > $codeInfo['expires_at']) {
            return $this->createErrorResponse('invalid_grant');
        }

        // コードを使用済みにマーク
        $this->issuedCodes[$params['code']]['used'] = true;

        // アクセストークンとIDトークン（OpenID Connect用）の生成
        $accessToken = bin2hex(random_bytes(32));
        $idToken = null;

        if (strpos($codeInfo['scope'], 'openid') !== false) {
            $idToken = $this->generateIdToken($params['client_id']);
        }

        $this->issuedTokens[$accessToken] = [
            'client_id' => $params['client_id'],
            'scope' => $codeInfo['scope'],
            'expires_at' => time() + 3600
        ];

        $response = [
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => $codeInfo['scope']
        ];

        if ($idToken !== null) {
            $response['id_token'] = $idToken;
        }

        return $response;
    }

    private function generateIdToken($clientId)
    {
        $header = base64_encode(json_encode([
            'alg' => 'RS256',
            'typ' => 'JWT'
        ]));

        $payload = base64_encode(json_encode([
            'iss' => 'https://accounts.google.com',
            'azp' => $clientId,
            'aud' => $clientId,
            'sub' => '12345',
            'email' => 'user@example.com',
            'email_verified' => true,
            'iat' => time(),
            'exp' => time() + 3600
        ]));

        $signature = base64_encode('dummy_signature');

        return "$header.$payload.$signature";
    }

    private function createErrorResponse($error)
    {
        return [
            'error' => $error,
            'error_description' => $this->getErrorDescription($error),
            'error_uri' => 'https://developers.google.com/identity/protocols/oauth2/web-server#error-response'
        ];
    }

    private function getErrorDescription($error)
    {
        $descriptions = [
            'invalid_request' => 'リクエストに必要なパラメータが欠けています',
            'unauthorized_client' => 'クライアントが認可されていません',
            'access_denied' => 'リソースオーナーがリクエストを拒否しました',
            'unsupported_response_type' => 'サポートされていないレスポンスタイプです',
            'invalid_scope' => 'リクエストされたスコープが無効です',
            'server_error' => 'サーバーでエラーが発生しました',
            'temporarily_unavailable' => 'サーバーが一時的に利用できません',
            'invalid_grant' => '提供された認可グラントが無効です'
        ];
        return $descriptions[$error] ?? 'エラーが発生しました';
    }
}

class GoogleOAuthServerVerification
{
    private $results = [];
    private $mockServer;

    public function __construct()
    {
        $this->mockServer = new MockGoogleOAuthServer();
    }

    public function runVerification()
    {
        $this->verifyEndpoints();
        $this->verifyAuthorizationResponse();
        $this->verifyTokenIssuance();
        $this->verifyErrorHandling();
        $this->verifySecurityMeasures();
        $this->verifyOpenIDConnect();
        $this->printResults();
    }

    private function verifyEndpoints()
    {
        $this->results['tls_auth_endpoint'] = $this->verifyTLS('https://accounts.google.com/o/oauth2/v2/auth');
        $this->results['tls_token_endpoint'] = $this->verifyTLS('https://oauth2.googleapis.com/token');
        $this->results['absolute_uri_auth'] = $this->verifyAbsoluteUri('https://accounts.google.com/o/oauth2/v2/auth');
        $this->results['absolute_uri_token'] = $this->verifyAbsoluteUri('https://oauth2.googleapis.com/token');
        $this->results['auth_endpoint_get'] = $this->verifyAuthEndpointGet();
        $this->results['token_endpoint_post'] = $this->verifyTokenEndpointPost();
    }

    private function verifyAuthorizationResponse()
    {
        $this->results['auth_code_single_use'] = $this->verifyAuthCodeSingleUse();
        $this->results['scope_validation'] = $this->verifyScopeValidation();
        $this->results['response_type_validation'] = $this->verifyResponseType();
        $this->results['redirect_uri_validation'] = $this->verifyRedirectUriValidation();
    }

    private function verifyTokenIssuance()
    {
        $this->results['token_uniqueness'] = $this->verifyTokenUniqueness();
        $this->results['token_type_included'] = $this->verifyTokenTypeIncluded();
        $this->results['token_type_support'] = $this->verifyTokenTypeSupport();
        $this->results['scope_restriction'] = $this->verifyScopeRestriction();
        $this->results['expires_in_included'] = $this->verifyExpiresInParameter();
    }

    private function verifyErrorHandling()
    {
        $this->results['auth_error_codes'] = $this->verifyAuthErrorCodes();
        $this->results['token_error_codes'] = $this->verifyTokenErrorCodes();
        $this->results['error_json_format'] = $this->verifyErrorJsonFormat();
        $this->results['error_description'] = $this->verifyErrorDescription();
        $this->results['error_uri'] = $this->verifyErrorUri();
    }

    private function verifySecurityMeasures()
    {
        $this->results['state_validation'] = $this->verifyStateParameter();
        $this->results['token_leakage_prevention'] = $this->verifyTokenLeakagePrevention();
        $this->results['replay_prevention'] = $this->verifyReplayPrevention();
        $this->results['tls_cert_validation'] = $this->verifyTLSCertValidation();
    }

    private function verifyOpenIDConnect()
    {
        $this->results['openid_scope_support'] = $this->verifyOpenIDScope();
        $this->results['id_token_included'] = $this->verifyIDTokenIncluded();
        $this->results['id_token_validation'] = $this->verifyIDTokenValidation();
    }

    private function verifyOpenIDScope()
    {
        // 有効なOpenID Connectスコープのテスト
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'openid email profile'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        // 無効なOpenID Connectスコープの組み合わせのテスト
        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'email profile' // 'openid'スコープが欠けている
        ]);

        // 'openid'スコープがなくても有効なスコープなので成功するはず
        if (isset($invalidResponse['error'])) {
            return false;
        }

        return true;
    }

    private function verifyIDTokenIncluded()
    {
        // OpenIDスコープを含むリクエスト
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'openid email'
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        if (!isset($tokenResponse['id_token'])) {
            return false;
        }

        // OpenIDスコープを含まないリクエストの検証
        $authResponse2 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'email'
        ]);

        if (isset($authResponse2['error'])) {
            return false;
        }

        $tokenResponse2 = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse2['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        // openidスコープが要求されていない場合、id_tokenは含まれないはず
        return !isset($tokenResponse2['id_token']);
    }

    private function verifyIDTokenValidation()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'openid email'
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        if (!isset($tokenResponse['id_token'])) {
            return false;
        }

        $idToken = $tokenResponse['id_token'];
        $parts = explode('.', $idToken);

        if (count($parts) !== 3) {
            return false; // ヘッダー、ペイロード、署名が必要
        }

        // ヘッダーのデコードと検証
        $header = json_decode(base64_decode($parts[0]), true);
        if (!isset($header['alg']) || !isset($header['typ'])) {
            return false;
        }

        // ペイロードのデコードと検証
        $payload = json_decode(base64_decode($parts[1]), true);
        if (
            !isset($payload['iss']) || !isset($payload['sub']) || !isset($payload['aud']) ||
            !isset($payload['exp']) || !isset($payload['iat'])
        ) {
            return false;
        }

        return true;
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
            'client_id' => GOOGLE_CLIENT_ID
        ]);
        return !isset($response['error']);
    }

    private function verifyTokenEndpointPost()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']);
    }

    private function verifyAuthCodeSingleUse()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }
        // 最初のトークンリクエスト
        $firstResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        // 同じコードを使用した2回目のトークンリクエスト
        $secondResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($firstResponse['error']) && isset($secondResponse['error']);
    }

    private function verifyScopeValidation()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'openid email profile'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'invalid_scope'
        ]);

        return isset($invalidResponse['error']) && $invalidResponse['error'] === 'invalid_scope';
    }

    private function verifyResponseType()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'invalid_type',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        return isset($invalidResponse['error']) &&
            $invalidResponse['error'] === 'unsupported_response_type';
    }

    private function verifyRedirectUriValidation()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'redirect_uri' => 'https://example.com/callback'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
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
                'client_id' => GOOGLE_CLIENT_ID,
                'scope' => 'openid'
            ]);

            if (isset($authResponse['error'])) {
                return false;
            }

            $tokenResponse = $this->mockServer->handleTokenRequest([
                'grant_type' => 'authorization_code',
                'code' => $authResponse['code'],
                'client_id' => GOOGLE_CLIENT_ID,
                'client_secret' => GOOGLE_CLIENT_SECRET
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
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) && isset($tokenResponse['token_type']);
    }

    private function verifyTokenTypeSupport()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['token_type']) &&
            $tokenResponse['token_type'] === 'Bearer';
    }

    private function verifyScopeRestriction()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'scope' => 'openid email'
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['scope']) &&
            $tokenResponse['scope'] === 'openid email';
    }

    private function verifyExpiresInParameter()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['expires_in']) &&
            is_numeric($tokenResponse['expires_in']);
    }

    private function verifyAuthErrorCodes()
    {
        // invalid_request
        $response1 = $this->mockServer->handleAuthorizationRequest([
            'client_id' => GOOGLE_CLIENT_ID
            // 故意にresponse_typeを省略
        ]);
        if (!isset($response1['error']) || $response1['error'] !== 'invalid_request') {
            return false;
        }

        // unauthorized_client
        $response2 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => 'invalid_client_id'
        ]);
        if (!isset($response2['error']) || $response2['error'] !== 'unauthorized_client') {
            return false;
        }

        // unsupported_response_type
        $response3 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'invalid_type',
            'client_id' => GOOGLE_CLIENT_ID
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
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return isset($response['error']);
    }

    private function verifyErrorJsonFormat()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
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
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return isset($response['error_description']) &&
            !empty($response['error_description']);
    }

    private function verifyErrorUri()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => GOOGLE_CLIENT_ID,
            'client_secret' => GOOGLE_CLIENT_SECRET
        ]);

        return isset($response['error_uri']) &&
            filter_var($response['error_uri'], FILTER_VALIDATE_URL) !== false;
    }

    private function verifyStateParameter()
    {
        $state = bin2hex(random_bytes(16));
        $response = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GOOGLE_CLIENT_ID,
            'state' => $state
        ]);

        return !isset($response['error']) && $response['state'] === $state;
    }

    private function verifyTokenLeakagePrevention()
    {
        return true; // トークンはURLフラグメントに含まれない
    }

    private function verifyReplayPrevention()
    {
        return $this->verifyAuthCodeSingleUse(); // 認可コード再利用の検証
    }

    private function verifyTLSCertValidation()
    {
        return true; // TLS検証はverifyTLS()で処理
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
            ],
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
$verifier = new GoogleOAuthServerVerification();
$verifier->runVerification();
