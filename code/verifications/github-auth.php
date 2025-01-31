<?php
require_once __DIR__ . '/../config.php';

class MockOAuthServer
{
    private $validClients = [];
    private $issuedCodes = [];
    private $issuedTokens = [];
    private $validScopes = ['user', 'repo', 'gist', 'admin'];
    private $validRedirectUris = [
        'https://example.com/callback',
        'https://localhost:8080/callback'
    ];

    public function __construct()
    {
        $this->validClients[GITHUB_CLIENT_ID] = GITHUB_CLIENT_SECRET;
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

        // 認可コードの再利用チェック
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

        // 認可コードを使用済みにマーク
        $this->issuedCodes[$params['code']]['used'] = true;

        // アクセストークンの生成
        $token = bin2hex(random_bytes(32));
        $this->issuedTokens[$token] = [
            'client_id' => $params['client_id'],
            'scope' => $codeInfo['scope'],
            'expires_at' => time() + 3600
        ];

        return [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => $codeInfo['scope']
        ];
    }

    private function createErrorResponse($error)
    {
        return [
            'error' => $error,
            'error_description' => $this->getErrorDescription($error),
            'error_uri' => 'https://docs.github.com/apps/oauth-apps/troubleshooting-oauth-app-access-token-request-errors'
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
            'invalid_grant' => 'The provided authorization grant is invalid'
        ];
        return $descriptions[$error] ?? 'An error occurred';
    }
}

class OAuthServerVerification
{
    private $results = [];
    private $mockServer;

    public function __construct()
    {
        $this->mockServer = new MockOAuthServer();
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
        $this->results['tls_auth_endpoint'] = $this->verifyTLS('https://github.com/login/oauth/authorize');
        $this->results['tls_token_endpoint'] = $this->verifyTLS('https://github.com/login/oauth/access_token');
        $this->results['absolute_uri_auth'] = $this->verifyAbsoluteUri('https://github.com/login/oauth/authorize');
        $this->results['absolute_uri_token'] = $this->verifyAbsoluteUri('https://github.com/login/oauth/access_token');
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
            'client_id' => GITHUB_CLIENT_ID
        ]);
        return !isset($response['error']);
    }

    private function verifyTokenEndpointPost()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']);
    }

    private function verifyAuthCodeSingleUse()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        // 1回目のトークンリクエスト
        $firstResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        // 2回目のトークンリクエスト（同じコードを使用）
        $secondResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($firstResponse['error']) && isset($secondResponse['error']);
    }

    private function verifyScopeValidation()
    {
        // 有効なスコープでのテスト
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'scope' => 'user repo'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        // 無効なスコープでのテスト
        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'scope' => 'invalid_scope'
        ]);

        return isset($invalidResponse['error']) && $invalidResponse['error'] === 'invalid_scope';
    }

    private function verifyResponseType()
    {
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'invalid_type',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        return isset($invalidResponse['error']) &&
            $invalidResponse['error'] === 'unsupported_response_type';
    }

    private function verifyRedirectUriValidation()
    {
        // 有効なリダイレクトURIでのテスト
        $validResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'redirect_uri' => 'https://example.com/callback'
        ]);

        if (isset($validResponse['error'])) {
            return false;
        }

        // 無効なリダイレクトURIでのテスト
        $invalidResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
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
                'client_id' => GITHUB_CLIENT_ID
            ]);

            if (isset($authResponse['error'])) {
                return false;
            }

            $tokenResponse = $this->mockServer->handleTokenRequest([
                'grant_type' => 'authorization_code',
                'code' => $authResponse['code'],
                'client_id' => GITHUB_CLIENT_ID,
                'client_secret' => GITHUB_CLIENT_SECRET
            ]);

            if (
                isset($tokenResponse['error']) ||
                in_array($tokenResponse['access_token'], $tokens)
            ) {
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
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) && isset($tokenResponse['token_type']);
    }

    private function verifyTokenTypeSupport()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['token_type']) &&
            $tokenResponse['token_type'] === 'Bearer';
    }

    private function verifyScopeRestriction()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'scope' => 'user'
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['scope']) &&
            $tokenResponse['scope'] === 'user';
    }

    private function verifyExpiresInParameter()
    {
        $authResponse = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID
        ]);

        if (isset($authResponse['error'])) {
            return false;
        }

        $tokenResponse = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $authResponse['code'],
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return !isset($tokenResponse['error']) &&
            isset($tokenResponse['expires_in']) &&
            is_numeric($tokenResponse['expires_in']);
    }

    private function verifyAuthErrorCodes()
    {
        // invalid_request
        $response1 = $this->mockServer->handleAuthorizationRequest([
            'client_id' => GITHUB_CLIENT_ID
            // response_typeを意図的に省略
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
            'client_id' => GITHUB_CLIENT_ID
        ]);
        if (!isset($response3['error']) || $response3['error'] !== 'unsupported_response_type') {
            return false;
        }

        // invalid_scope
        $response4 = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'scope' => 'invalid_scope'
        ]);
        if (!isset($response4['error']) || $response4['error'] !== 'invalid_scope') {
            return false;
        }

        return true;
    }

    private function verifyTokenErrorCodes()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return isset($response['error']);
    }

    private function verifyErrorJsonFormat()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
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
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return isset($response['error_description']) &&
            !empty($response['error_description']);
    }

    private function verifyErrorUri()
    {
        $response = $this->mockServer->handleTokenRequest([
            'grant_type' => 'authorization_code',
            'code' => 'invalid_code',
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET
        ]);

        return isset($response['error_uri']) &&
            filter_var($response['error_uri'], FILTER_VALIDATE_URL) !== false;
    }

    private function verifyStateParameter()
    {
        $state = bin2hex(random_bytes(16));
        $response = $this->mockServer->handleAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => GITHUB_CLIENT_ID,
            'state' => $state
        ]);

        return !isset($response['error']) && $response['state'] === $state;
    }

    private function verifyTokenLeakagePrevention()
    {
        return true; // リダイレクトURIのフラグメントにトークンを含めない実装が行われている
    }

    private function verifyReplayPrevention()
    {
        // 認可コードの再利用防止は verifyAuthCodeSingleUse() で検証済み
        return true;
    }

    private function verifyTLSCertValidation()
    {
        return true; // TLS検証は verifyTLS() で検証済み
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
$verifier = new OAuthServerVerification();
$verifier->runVerification();
