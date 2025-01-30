<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ダッシュボード</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #f5f5f5;
        }
        .dashboard {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .user-info {
            display: flex;
            align-items: center;
            margin-bottom: 2rem;
        }
        .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin-right: 1rem;
        }
        .logout {
            background-color: #dc3545;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            text-decoration: none;
            display: inline-block;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <?php
    require_once 'config.php';
    
    if (!isset($_SESSION['user'])) {
        header('Location: index.php');
        exit;
    }
    
    $user = $_SESSION['user'];
    ?>
    <div class="dashboard">
        <div class="user-info">
            <img src="<?php echo htmlspecialchars($user['avatar_url']); ?>" alt="Profile" class="avatar">
            <div>
                <h1>ようこそ、<?php echo htmlspecialchars($user['login']); ?>さん</h1>
                <p>名前: <?php echo htmlspecialchars($user['name'] ?? 'Not set'); ?></p>
                <p>メール: <?php echo htmlspecialchars($user['email'] ?? 'Not public'); ?></p>
            </div>
        </div>
        <a href="logout.php" class="logout">ログアウト</a>
    </div>
</body>
</html>
