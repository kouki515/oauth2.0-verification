<?php

namespace OAuthVerification;

// OAuth プロバイダーが実装すべきインターフェース
// 各プロバイダー（GitHub, Google等）はこのインターフェースを実装する
interface OAuthProviderInterface {
    // 認可URLを生成するメソッド（ユーザーがアクセスする認可画面のURL）
    public function getAuthorizationUrl(array $params): string;
    // 認可コードを使用してアクセストークンを取得するメソッド
    public function getAccessToken(string $code): array;
    // アクセストークンの有効性を検証するメソッド
    public function validateAccessToken(string $token): bool;
    // リソースエンドポイントのURLを取得するメソッド
    public function getResourceEndpoint(): string;
}

// GitHubのOAuth実装クラス
class GitHubProvider implements OAuthProviderInterface {
    private string $clientId;        // GitHubアプリケーションのクライアントID
    private string $clientSecret;    // GitHubアプリケーションのクライアントシークレット
    private string $redirectUri;     // 認可後のリダイレクト先URI
    
    // コンストラクタ：認証に必要な情報を初期化
    public function __construct(string $clientId, string $clientSecret, string $redirectUri) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
    }
    
    // GitHub認可エンドポイントのURL生成メソッド
    public function getAuthorizationUrl(array $params = []): string {
        // GitHubの認可エンドポイントベースURL
        $baseUrl = 'https://github.com/login/oauth/authorize';
        // デフォルトのパラメータ設定
        $defaultParams = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',      // 認可コードフローを使用
            'scope' => 'read:user'          // ユーザー情報の読み取り権限を要求
        ];
        
        // デフォルトパラメータと追加パラメータを結合してURLを生成
        return $baseUrl . '?' . http_build_query(array_merge($defaultParams, $params));
    }
    
    // アクセストークン取得メソッド
    public function getAccessToken(string $code): array {
        // GitHubのトークンエンドポイントにPOSTリクエストを送信
        $response = $this->makeRequest('POST', 'https://github.com/login/oauth/access_token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,                // 認可コード
            'redirect_uri' => $this->redirectUri
        ]);
        
        // レスポンスをJSON形式で解析して返却
        return json_decode($response, true);
    }
    
    // アクセストークンの有効性検証メソッド
    public function validateAccessToken(string $token): bool {
        try {
            // ユーザー情報エンドポイントにアクセスしてトークンの有効性を確認
            $response = $this->makeRequest('GET', 'https://api.github.com/user', [], [
                'Authorization: Bearer ' . $token
            ]);
            return !empty($response);
        } catch (\Exception $e) {
            return false;   // エラーが発生した場合はトークンが無効と判断
        }
    }
    
    // GitHubのユーザー情報エンドポイントURLを返却
    public function getResourceEndpoint(): string {
        return 'https://api.github.com/user';
    }
    
    // HTTPリクエストを実行する内部メソッド
    private function makeRequest(string $method, string $url, array $params = [], array $headers = []): string {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // デフォルトのヘッダーとカスタムヘッダーを設定
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge([
            'Accept: application/json',
            'User-Agent: OAuth-Verification-Tool'
        ], $headers));
        
        // POSTリクエストの場合のパラメータ設定
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }
        
        // リクエストを実行して結果を返却
        $response = curl_exec($ch);
        curl_close($ch);
        
        return $response;
    }
}

// OAuth検証実行クラス
class OAuthVerifier {
    private OAuthProviderInterface $provider;  // 検証対象のOAuthプロバイダー
    private array $testResults = [];           // 検証結果を格納する配列
    
    public function __construct(OAuthProviderInterface $provider) {
        $this->provider = $provider;
    }
    
    // 認可エンドポイントの検証メソッド
    public function verifyAuthorizationEndpoint(): void {
        $this->testResults['auth_endpoint'] = [];
        
        // テストケース1: 正常なリクエストURL生成
        $validUrl = $this->provider->getAuthorizationUrl([]);
        $this->testResults['auth_endpoint']['valid_request'] = $this->validateUrl($validUrl);
        
        // テストケース2: 必須パラメータ欠如時の挙動
        $invalidUrl = $this->provider->getAuthorizationUrl(['client_id' => '']);
        $this->testResults['auth_endpoint']['missing_params'] = $this->validateUrl($invalidUrl);
    }
    
    // トークンエンドポイントの検証メソッド
    public function verifyTokenEndpoint(string $code): void {
        $this->testResults['token_endpoint'] = [];
        
        try {
            // アクセストークン取得テスト
            $response = $this->provider->getAccessToken($code);
            $this->testResults['token_endpoint']['valid_request'] = !empty($response['access_token']);
        } catch (\Exception $e) {
            $this->testResults['token_endpoint']['valid_request'] = false;
        }
    }
    
    // 検証結果取得メソッド
    public function getResults(): array {
        return $this->testResults;
    }
    
    // URLの形式を検証する内部メソッド
    private function validateUrl(string $url): bool {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
}

// 使用例：プログラムの実行方法
$config = [
    'client_id' => 'your_client_id',         // GitHubで取得したクライアントID
    'client_secret' => 'your_client_secret', // GitHubで取得したクライアントシークレット
    'redirect_uri' => 'http://localhost/callback' // コールバックURL
];

// GitHubプロバイダーのインスタンス生成
$provider = new GitHubProvider($config['client_id'], $config['client_secret'], $config['redirect_uri']);
// 検証実行クラスのインスタンス生成
$verifier = new OAuthVerifier($provider);

// 認可エンドポイントの検証を実行
$verifier->verifyAuthorizationEndpoint();
// 注意：以下のコードはコールバックでcode取得後に実行
// $verifier->verifyTokenEndpoint($code);

// 検証結果の取得
$results = $verifier->getResults();
