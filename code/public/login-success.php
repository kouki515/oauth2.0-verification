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
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
        <?php if ($_SESSION['oauth_provider'] === 'github'): ?>
            <p>ユーザー名: <?php echo htmlspecialchars($_SESSION['user']['login']); ?></p>
        <?php else: ?>
            <p>名前: <?php echo htmlspecialchars($_SESSION['user']['name']); ?></p>
            <p>メールアドレス: <?php echo htmlspecialchars($_SESSION['user']['email']); ?></p>
        <?php endif; ?>
        <a href="?logout=1" class="logout-button">ログアウト</a>
    </div>
</body>

</html>
