<?php
/**
 * FABER – Atelier de Consultanță
 * admin/setup.php — Utilitar de configurare inițială
 *
 * Rulați o singură dată pentru a genera hash-ul parolei admin.
 * ȘTERGEȚI sau DEZACTIVAȚI după utilizare!
 *
 * Acces: https://atelierdeconsultanta.ro/admin/setup.php
 */

declare(strict_types=1);

// ── Protecție: dezactivat în producție ────────────────────────
$setupToken = $_GET['token'] ?? '';
// Schimbați acest token înainte de a folosi scriptul!
define('SETUP_TOKEN', 'SCHIMBATI_ACEST_TOKEN_INAINTE_DE_UTILIZARE');

if ($setupToken !== SETUP_TOKEN) {
    http_response_code(403);
    exit('<h2>Acces interzis. Adăugați ?token=SETUP_TOKEN în URL.</h2>');
}

$message = '';
$envContent = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $confirm  = trim($_POST['confirm'] ?? '');

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = '<div class="error">Email invalid.</div>';
    } elseif (strlen($password) < 8) {
        $message = '<div class="error">Parola trebuie să aibă minim 8 caractere.</div>';
    } elseif ($password !== $confirm) {
        $message = '<div class="error">Parolele nu coincid.</div>';
    } else {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $envContent = "ADMIN_EMAIL={$email}\nADMIN_PASSWORD_HASH={$hash}\n";

        // Salvăm în .env
        $envFile = __DIR__ . '/../.env';
        $existing = file_exists($envFile) ? file_get_contents($envFile) : '';
        // Eliminăm liniile vechi ADMIN_*
        $existing = preg_replace('/^ADMIN_(EMAIL|PASSWORD_HASH)=.*\n?/m', '', $existing);
        file_put_contents($envFile, trim($existing) . "\n" . $envContent);

        $message = '<div class="success">✅ Credențialele au fost salvate în .env! Ștergeți setup.php acum.</div>';
    }
}
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="robots" content="noindex,nofollow">
<title>FABER Admin Setup</title>
<style>
  body{font-family:sans-serif;max-width:500px;margin:60px auto;padding:0 20px}
  h1{color:#0d1f3c}
  .error{background:#fef2f2;border:1px solid #fca5a5;color:#dc2626;padding:10px;border-radius:6px;margin:10px 0}
  .success{background:#dcfce7;border:1px solid #86efac;color:#16a34a;padding:10px;border-radius:6px;margin:10px 0}
  label{display:block;margin-top:12px;font-weight:600;font-size:.9rem}
  input{width:100%;padding:8px;border:1px solid #ccc;border-radius:6px;font-size:1rem;box-sizing:border-box;margin-top:4px}
  button{margin-top:16px;padding:10px 20px;background:#e8642a;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer}
  pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow-x:auto;font-size:.85rem}
  .warn{background:#fef3c7;border:1px solid #fcd34d;color:#92400e;padding:10px;border-radius:6px;margin:10px 0}
</style>
</head>
<body>
<h1>FABER Admin — Setup parolă</h1>
<div class="warn">⚠️ Ștergeți acest fișier după ce ați configurat credențialele!</div>
<?= $message ?>
<?php if ($envContent): ?>
<p>Conținut adăugat în <code>.env</code>:</p>
<pre><?= htmlspecialchars($envContent) ?></pre>
<?php endif; ?>
<form method="post">
  <label>Email admin</label>
  <input type="email" name="email" required placeholder="email@exemplu.ro">
  <label>Parolă nouă (minim 8 caractere)</label>
  <input type="password" name="password" required minlength="8">
  <label>Confirmă parola</label>
  <input type="password" name="confirm" required minlength="8">
  <button type="submit">Generează și salvează</button>
</form>
</body>
</html>
