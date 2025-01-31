<?php
session_start();
require_once 'config.php';

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

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
    $_SESSION['user'] = $user;
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>ログイン成功</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background-color: #f6f8fa;
            }
            .profile-container {
                background: white;
                padding: 40px;
                border-radius: 6px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }
            .logout-button {
                background-color: #dc3545;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
            .logout-button:hover {
                background-color: #c82333;
            }
        </style>
    </head>
    <body>
        <div class="profile-container">
            <h2>ログイン成功！</h2>
            <p>ユーザー名: <?php echo htmlspecialchars($user['login']); ?></p>
            <a href="?logout=1" class="logout-button">ログアウト</a>
        </div>
    </body>
    </html>
    <?php
} else {
    echo "認証エラー";
}
?>
