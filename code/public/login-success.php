<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ログイン成功</title>
    <style>
        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f6f8fa;
            color: #24292e;
        }

        .profile-container {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }

        .success-icon {
            color: #28a745;
            font-size: 48px;
            margin-bottom: 1rem;
        }

        .user-info {
            margin: 1.5rem 0;
            padding: 1.5rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            text-align: left;
        }

        .user-info p {
            margin: 0.5rem 0;
            padding: 0.5rem 0;
            border-bottom: 1px solid #e1e4e8;
        }

        .user-info p:last-child {
            border-bottom: none;
        }

        .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            margin-bottom: 1rem;
            border: 3px solid #fff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .provider-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 1rem;
        }

        .provider-github {
            background-color: #24292e;
            color: white;
        }

        .provider-google {
            background-color: #4285f4;
            color: white;
        }

        .provider-discord {
            background-color: #7289DA;
            color: white;
        }

        .logout-button {
            background-color: #dc3545;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            text-decoration: none;
            display: inline-block;
            margin-top: 1rem;
            font-weight: 500;
            transition: background-color 0.2s ease;
        }

        .logout-button:hover {
            background-color: #c82333;
        }

        @media (max-width: 480px) {
            .profile-container {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <?php
    if (!isset($_SESSION['user']) || !isset($_SESSION['oauth_provider'])) {
        header('Location: index.php');
        exit;
    }
    
    $provider = $_SESSION['oauth_provider'];
    $user = $_SESSION['user'];
    
    // プロバイダー表示名を設定
    $provider_display = [
        'github' => 'GitHub',
        'google' => 'Google',
        'discord' => 'Discord'
    ][$provider] ?? $provider;
    
    // アバター画像のURLを取得
    $avatar_url = '';
    switch ($provider) {
        case 'github':
            $avatar_url = $user['avatar_url'] ?? '';
            break;
        case 'google':
            $avatar_url = $user['picture'] ?? '';
            break;
        case 'discord':
            $avatar_url = $user['avatar'] ? 
                "https://cdn.discordapp.com/avatars/{$user['id']}/{$user['avatar']}.png" : '';
            break;
    }
    ?>
    <div class="profile-container">
        <h2>ログイン成功！</h2>
        <div class="provider-badge provider-<?= htmlspecialchars($provider) ?>">
            <?= htmlspecialchars($provider_display) ?>でログイン中
        </div>
        
        <?php if ($avatar_url): ?>
        <img src="<?= htmlspecialchars($avatar_url) ?>" alt="プロフィール画像" class="avatar">
        <?php endif; ?>

        <div class="user-info">
            <?php switch($provider): 
                case 'github': ?>
                    <p><strong>ユーザー名:</strong> <?= htmlspecialchars($user['login']) ?></p>
                    <?php if (!empty($user['name'])): ?>
                        <p><strong>表示名:</strong> <?= htmlspecialchars($user['name']) ?></p>
                    <?php endif; ?>
                    <?php if (!empty($user['email'])): ?>
                        <p><strong>メール:</strong> <?= htmlspecialchars($user['email']) ?></p>
                    <?php endif; ?>
                    <?php break;
                
                case 'google': ?>
                    <p><strong>名前:</strong> <?= htmlspecialchars($user['name']) ?></p>
                    <p><strong>メール:</strong> <?= htmlspecialchars($user['email']) ?></p>
                    <?php break;
                
                case 'discord': ?>
                    <p><strong>ユーザー名:</strong> <?= htmlspecialchars($user['username']) ?></p>
                    <?php if (!empty($user['global_name'])): ?>
                        <p><strong>表示名:</strong> <?= htmlspecialchars($user['global_name']) ?></p>
                    <?php endif; ?>
                    <p><strong>メール:</strong> <?= htmlspecialchars($user['email']) ?></p>
                    <?php break;
                
                default: ?>
                    <p><strong>名前:</strong> <?= htmlspecialchars($user['name'] ?? 'Unknown') ?></p>
                    <?php if (!empty($user['email'])): ?>
                        <p><strong>メール:</strong> <?= htmlspecialchars($user['email']) ?></p>
                    <?php endif; ?>
            <?php endswitch; ?>
        </div>

        <a href="?logout=1" class="logout-button">ログアウト</a>
    </div>
</body>
</html>
