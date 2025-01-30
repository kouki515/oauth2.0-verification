<?php
require_once 'config.php';

if (!isset($_GET['code'])) {
    die('認可コードがありません');
}

if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $_GET['state']) {
    die('不正なリクエストです');
}

$code = $_GET['code'];

// アクセストークンの取得
$token_url = 'https://github.com/login/oauth/access_token';
$params = [
    'client_id' => GITHUB_CLIENT_ID,
    'client_secret' => GITHUB_CLIENT_SECRET,
    'code' => $code,
    'redirect_uri' => REDIRECT_URI
];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $token_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Accept: application/json'
]);

$response = curl_exec($ch);
curl_close($ch);

$token_data = json_decode($response, true);

if (!isset($token_data['access_token'])) {
    die('アクセストークンの取得に失敗しました');
}

// ユーザー情報の取得
$user_url = 'https://api.github.com/user';
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $user_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: Bearer ' . $token_data['access_token'],
    'User-Agent: PHP OAuth Client'
]);

$response = curl_exec($ch);
curl_close($ch);

$user_data = json_decode($response, true);

if (!isset($user_data['login'])) {
    die('ユーザー情報の取得に失敗しました');
}

$_SESSION['user'] = $user_data;
header('Location: dashboard.php');
exit;
