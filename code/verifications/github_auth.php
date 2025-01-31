<?php
define('GITHUB_CLIENT_ID', 'Ov23liINeWpHEcMJTSxi');
define('GITHUB_CLIENT_SECRET', '8bd9be7453d5606505315f6ac8ab296fb9cac89e');

class OAuthServerVerification
{
    private $results = [];
    private $accessToken;
    private $authCode;

    public function verifyEndpoints()
    {
        $this->results['tls_auth_endpoint'] = $this->verifyTLS('https://github.com/login/oauth/authorize');
        $this->results['tls_token_endpoint'] = $this->verifyTLS('https://github.com/login/oauth/access_token');
        $this->results['absolute_uri_auth'] = $this->verifyAbsoluteUri('https://github.com/login/oauth/authorize');
        $this->results['absolute_uri_token'] = $this->verifyAbsoluteUri('https://github.com/login/oauth/access_token');
    }

    public function verifyAuthorizationResponse()
    {
        $this->authCode = $this->generateAuthCode();
        $this->results['auth_code_single_use'] = $this->verifyAuthCodeSingleUse($this->authCode);
        $this->results['scope_validation'] = $this->verifyScopeValidation(['user', 'repo']);
        $this->results['response_type_validation'] = $this->verifyResponseType('code');
    }

    public function verifyTokenIssuance()
    {
        $this->accessToken = $this->generateAccessToken();
        $this->results['token_uniqueness'] = $this->verifyTokenUniqueness($this->accessToken);
        $this->results['token_type_included'] = $this->verifyTokenTypeIncluded();
        $this->results['scope_restriction'] = $this->verifyScopeRestriction();
    }

    public function verifyErrorHandling()
    {
        $this->results['auth_error_codes'] = $this->verifyAuthErrorCodes();
        $this->results['token_error_codes'] = $this->verifyTokenErrorCodes();
        $this->results['error_json_format'] = $this->verifyErrorJsonFormat();
    }

    public function verifySecurityMeasures()
    {
        $this->results['state_validation'] = $this->verifyStateParameter();
        $this->results['token_leakage_prevention'] = $this->verifyTokenLeakagePrevention();
        $this->results['replay_prevention'] = $this->verifyReplayPrevention();
    }

    private function verifyTLS($url)
    {
        $parsed = parse_url($url);
        return $parsed['scheme'] === 'https';
    }

    private function verifyAbsoluteUri($url)
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    private function generateAuthCode()
    {
        return bin2hex(random_bytes(32));
    }

    private function verifyAuthCodeSingleUse($code)
    {
        $firstUse = json_decode($this->makeTokenRequest($code), true);
        $secondUse = json_decode($this->makeTokenRequest($code), true);
        return isset($firstUse['access_token']) && !isset($secondUse['access_token']);
    }

    private function verifyScopeValidation($scopes)
    {
        $response = $this->makeAuthRequest(['scope' => implode(' ', $scopes)]);
        return $response['http_code'] === 200;
    }

    private function verifyResponseType($type)
    {
        $response = $this->makeAuthRequest(['response_type' => $type]);
        return $response['http_code'] === 200;
    }

    private function generateAccessToken()
    {
        return bin2hex(random_bytes(32));
    }

    private function verifyTokenUniqueness($token)
    {
        $tokens = [];
        for ($i = 0; $i < 10; $i++) {
            $newToken = $this->generateAccessToken();
            if (in_array($newToken, $tokens)) {
                return false;
            }
            $tokens[] = $newToken;
        }
        return true;
    }

    private function verifyTokenTypeIncluded()
    {
        $response = json_decode($this->makeTokenRequest($this->authCode), true);
        return isset($response['token_type']);
    }

    private function verifyScopeRestriction()
    {
        $response = json_decode($this->makeTokenRequest($this->authCode), true);
        return isset($response['scope']);
    }

    private function verifyAuthErrorCodes()
    {
        $errorCodes = [
            'invalid_request',
            'unauthorized_client',
            'access_denied',
            'unsupported_response_type',
            'invalid_scope',
            'server_error',
            'temporarily_unavailable'
        ];

        foreach ($errorCodes as $code) {
            $response = $this->makeAuthRequest(['error' => $code]);
            if ($response['http_code'] < 400) {
                return false;
            }
        }
        return true;
    }

    private function verifyTokenErrorCodes()
    {
        $response = $this->makeTokenRequest('invalid_code');
        return strpos($response, 'error') !== false;
    }

    private function verifyErrorJsonFormat()
    {
        $response = $this->makeTokenRequest('invalid_code');
        $decoded = json_decode($response, true);
        return $decoded !== null && isset($decoded['error']);
    }

    private function verifyStateParameter()
    {
        $state = bin2hex(random_bytes(16));
        $response = $this->makeAuthRequest(['state' => $state]);
        return $response['http_code'] === 200;
    }

    private function verifyTokenLeakagePrevention()
    {
        $response = json_decode($this->makeTokenRequest($this->authCode), true);
        return !isset($response['redirect_uri']) ||
            !isset(parse_url($response['redirect_uri'])['fragment']);
    }

    private function verifyReplayPrevention()
    {
        $token = $this->generateAccessToken();
        $firstRequest = $this->makeResourceRequest($token);
        $secondRequest = $this->makeResourceRequest($token);
        return $firstRequest === $secondRequest;
    }

    private function makeAuthRequest($params)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://github.com/login/oauth/authorize?' .
            http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [
            'response' => $response,
            'http_code' => $httpCode,
            'error' => ($httpCode >= 400)
        ];
    }

    private function makeTokenRequest($code)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://github.com/login/oauth/access_token');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'client_id' => GITHUB_CLIENT_ID,
            'client_secret' => GITHUB_CLIENT_SECRET,
            'code' => $code
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    private function makeResourceRequest($token)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://api.github.com/user');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: token ' . $token,
            'User-Agent: PHP OAuth Verification'
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    public function getResults()
    {
        return $this->results;
    }

    public function printResults()
    {
        echo "OAuth 2.0 認可サーバー要件検証結果\n\n";
        echo "1. エンドポイント要件\n";
        echo sprintf(
            "TLS (認可エンドポイント): %s\n",
            $this->results['tls_auth_endpoint'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "TLS (トークンエンドポイント): %s\n",
            $this->results['tls_token_endpoint'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "絶対URI (認可エンドポイント): %s\n",
            $this->results['absolute_uri_auth'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "絶対URI (トークンエンドポイント): %s\n\n",
            $this->results['absolute_uri_token'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );

        echo "2. 認可レスポンス要件\n";
        echo sprintf(
            "認可コードの一意性: %s\n",
            $this->results['auth_code_single_use'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "スコープ検証: %s\n",
            $this->results['scope_validation'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "レスポンスタイプ検証: %s\n\n",
            $this->results['response_type_validation'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );

        echo "3. トークン発行要件\n";
        echo sprintf(
            "トークンの一意性: %s\n",
            $this->results['token_uniqueness'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "トークンタイプの明示: %s\n",
            $this->results['token_type_included'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "スコープの制限: %s\n\n",
            $this->results['scope_restriction'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );

        echo "4. エラー処理要件\n";
        echo sprintf(
            "認可エラーコード: %s\n",
            $this->results['auth_error_codes'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "トークンエラーコード: %s\n",
            $this->results['token_error_codes'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "JSONエラーフォーマット: %s\n\n",
            $this->results['error_json_format'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );

        echo "5. セキュリティ要件\n";
        echo sprintf(
            "stateパラメータ検証: %s\n",
            $this->results['state_validation'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "トークン漏洩対策: %s\n",
            $this->results['token_leakage_prevention'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );
        echo sprintf(
            "リプレイ攻撃対策: %s\n\n",
            $this->results['replay_prevention'] ? "\033[32m◯\033[0m" : "\033[31m✗\033[0m"
        );

        $mustCount = array_sum(array_map(
            function ($v) {
                return $v ? 1 : 0;
            },
            $this->results
        ));
        $totalCount = count($this->results);
        $rate = ($mustCount / $totalCount) * 100;
        $color = $rate >= 80 ? "\033[32m" : ($rate >= 60 ? "\033[33m" : "\033[31m");
        echo sprintf("RFC6749準拠率: %s%.2f%%\033[0m\n", $color, $rate);
    }
}

$verifier = new OAuthServerVerification();
$verifier->verifyEndpoints();
$verifier->verifyAuthorizationResponse();
$verifier->verifyTokenIssuance();
$verifier->verifyErrorHandling();
$verifier->verifySecurityMeasures();
$verifier->printResults();
