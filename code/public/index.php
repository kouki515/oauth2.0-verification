<?php
session_start();
require_once __DIR__ . '/../config.php';

?>
<!DOCTYPE html>
<html lang="ja">

<head>
    <meta charset="UTF-8">
    <title>OAuth2.0とは</title>
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

        .oauth-button {
            display: inline-block;
            color: white;
            padding: 12px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            margin: 10px;
            width: 200px;
        }

        .github-button {
            background-color: #24292e;
        }

        .github-button:hover {
            background-color: #2f363d;
        }

        .google-button {
            background-color: #4285f4;
        }

        .google-button:hover {
            background-color: #357abd;
        }
    </style>
</head>

<body>
    <div class="login-container">
        <h1>ログイン</h1>
        <p>ソーシャルアカウントでログインしてください</p>
        <?php
        $github_auth_url = 'https://github.com/login/oauth/authorize?'
            . 'client_id=' . GITHUB_CLIENT_ID
            . '&redirect_uri=' . urlencode(GITHUB_REDIRECT_URI)
            . '&scope=user';

        $google_auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?'
            . 'client_id=' . GOOGLE_CLIENT_ID
            . '&redirect_uri=' . urlencode(GOOGLE_REDIRECT_URI)
            . '&response_type=code'
            . '&scope=' . urlencode('https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email')
            . '&access_type=online';
        ?>
        <div>
            <a href="<?= htmlspecialchars($github_auth_url); ?>" class="oauth-button github-button">
                GitHubでログイン
            </a>
        </div>
        <div>
            <a href="<?= htmlspecialchars($google_auth_url); ?>" class="oauth-button google-button">
                Googleでログイン
            </a>
        </div>
    </div>
</body>

</html>
