<?php
session_start();
require_once 'config.php';

if (isset($_GET['code'])) {
    $code = $_GET['code'];

    // アクセストークンを取得
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://github.com/login/oauth/access_token');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => GITHUB_CLIENT_ID,
        'client_secret' => GITHUB_CLIENT_SECRET,
        'code' => $code,
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);

    $response = curl_exec($ch);
    curl_close($ch);

    $data = json_decode($response, true);
    $access_token = $data['access_token'];

    // ユーザー情報を取得
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.github.com/user');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: token ' . $access_token,
        'User-Agent: PHP OAuth Client'
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    $user = json_decode($response, true);

    echo "ログイン成功！<br>";
    echo "ユーザー名: " . htmlspecialchars($user['login']);
} else {
    echo "認証エラー";
}
