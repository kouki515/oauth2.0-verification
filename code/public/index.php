<?php
session_start();
require_once 'config.php';
?>
<!DOCTYPE html>
<html lang="ja">

<head>
    <meta charset="UTF-8">
    <title>GitHub OAuth ログイン</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }

        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .github-button {
            display: inline-block;
            background-color: #24292e;
            color: white;
            padding: 12px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
        }

        .github-button:hover {
            background-color: #2f363d;
        }
    </style>
</head>

<body>
    <div class="login-container">
        <h1>ログイン</h1>
        <p>GitHubアカウントでログインしてください</p>
        <?php
        $auth_url = 'https://github.com/login/oauth/authorize?'
        ?>
        <a href="<?= htmlspecialchars($auth_url); ?>client_id=<?= GITHUB_CLIENT_ID; ?>&redirect_uri=<?= urlencode(REDIRECT_URI); ?>&scope=user" class="github-button">
        GitHubでログイン
        </a>
    </div>
</body>

</html>
