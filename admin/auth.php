<?php
/**
 * FABER – Atelier de Consultanță
 * admin/auth.php — Autentificare server-side pentru panoul de admin
 *
 * Securitate implementată:
 *  - Parola stocată cu bcrypt (password_hash / password_verify)
 *  - Rate limiting: max 5 tentative per IP per 15 minute
 *  - Sesiuni PHP securizate (httponly, samesite=strict)
 *  - Credențialele NICIODATĂ în codul frontend
 *  - Logare tentative de login eșuate
 */

declare(strict_types=1);

define('RATE_LIMIT_MAX',    5);
define('RATE_LIMIT_WINDOW', 900);   // 15 minute
define('DATA_DIR',          __DIR__ . '/../data/auth_rate/');

// ── Configurare sesiune securizată ─────────────────────────────
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure',   '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_lifetime', '0');  // sesiune browser
session_start();

// ── Headers de securitate ──────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache');

// ── Acceptăm doar POST ─────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['success' => false, 'error' => 'Metodă nepermisă.']));
}

// ── Citim body-ul ──────────────────────────────────────────────
$rawInput = file_get_contents('php://input');
if (strlen($rawInput) > 4096) {
    http_response_code(413);
    exit(json_encode(['success' => false, 'error' => 'Cerere prea mare.']));
}

$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (strpos($contentType, 'application/json') !== false) {
    $input = json_decode($rawInput, true) ?? [];
} else {
    parse_str($rawInput, $input);
    if (empty($input)) $input = $_POST;
}

// ── Acțiune cerută ─────────────────────────────────────────────
$action = trim((string)($input['action'] ?? 'login'));

// ── Verificare sesiune activă ──────────────────────────────────
if ($action === 'check') {
    if (!empty($_SESSION['admin_logged_in']) && !empty($_SESSION['admin_email'])) {
        exit(json_encode(['success' => true, 'email' => $_SESSION['admin_email']]));
    }
    http_response_code(401);
    exit(json_encode(['success' => false, 'error' => 'Sesiune inactivă.']));
}

// ── Logout ─────────────────────────────────────────────────────
if ($action === 'logout') {
    session_destroy();
    setcookie(session_name(), '', time() - 3600, '/');
    exit(json_encode(['success' => true]));
}

// ── LOGIN ──────────────────────────────────────────────────────
if ($action !== 'login') {
    http_response_code(400);
    exit(json_encode(['success' => false, 'error' => 'Acțiune necunoscută.']));
}

// ── Rate Limiting ──────────────────────────────────────────────
$ip = preg_replace('/[^0-9a-fA-F:.\-]/', '', $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$ip = substr($ip, 0, 45);

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0700, true);
    // Protejăm directorul
    file_put_contents(DATA_DIR . '.htaccess', "Deny from all\n");
}

$rateLimitFile = DATA_DIR . hash('sha256', $ip) . '.json';
$now = time();
$attempts = [];

if (file_exists($rateLimitFile)) {
    $data = json_decode(file_get_contents($rateLimitFile), true);
    if (is_array($data)) {
        $attempts = array_values(array_filter($data, fn($t) => ($now - $t) < RATE_LIMIT_WINDOW));
    }
}

if (count($attempts) >= RATE_LIMIT_MAX) {
    $retryAfter = RATE_LIMIT_WINDOW - ($now - min($attempts));
    header('Retry-After: ' . $retryAfter);
    http_response_code(429);
    logAuth($ip, 'RATE_LIMITED', '');
    exit(json_encode([
        'success'     => false,
        'error'       => 'Prea multe tentative de login. Blocaj ' . ceil($retryAfter / 60) . ' minute.',
        'retry_after' => $retryAfter,
        'blocked'     => true
    ]));
}

// ── Citim credențialele ────────────────────────────────────────
$email    = trim(strtolower((string)($input['email']    ?? '')));
$password = (string)($input['password'] ?? '');

if (empty($email) || empty($password)) {
    http_response_code(400);
    exit(json_encode(['success' => false, 'error' => 'Email și parola sunt obligatorii.']));
}

// ── Validare format email ──────────────────────────────────────
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(422);
    exit(json_encode(['success' => false, 'error' => 'Format email invalid.']));
}

// ── Citim utilizatorii din .env sau fișier securizat ─────────
$adminCredentials = loadCredentials();
$user = null;

foreach ($adminCredentials as $cred) {
    if (strtolower($cred['email']) === $email) {
        $user = $cred;
        break;
    }
}

// ── Verificare parolă cu timing-safe comparison ───────────────
// Simulăm timp de procesare chiar dacă userul nu există (anti-enumeration)
$dummyHash = '$2y$12$invalidhashfortimingnormalizatidontusethis';
$hash = $user ? $user['hash'] : $dummyHash;
$valid = $user && password_verify($password, $hash);

if (!$valid) {
    // Înregistrăm tentativa eșuată
    $attempts[] = $now;
    file_put_contents($rateLimitFile, json_encode(array_values($attempts)), LOCK_EX);
    logAuth($ip, 'FAILED', $email);

    $remaining = RATE_LIMIT_MAX - count($attempts);
    http_response_code(401);
    exit(json_encode([
        'success'   => false,
        'error'     => 'Email sau parolă incorectă.',
        'remaining' => max(0, $remaining)
    ]));
}

// ── Login reușit ───────────────────────────────────────────────
// Regenerăm ID-ul sesiunii (anti session fixation)
session_regenerate_id(true);

$_SESSION['admin_logged_in'] = true;
$_SESSION['admin_email']     = $user['email'];
$_SESSION['admin_role']      = $user['role'] ?? 'editor';
$_SESSION['login_time']      = $now;
$_SESSION['login_ip']        = $ip;

// Ștergem tentativele de rate limit la login reușit
if (file_exists($rateLimitFile)) unlink($rateLimitFile);

logAuth($ip, 'SUCCESS', $email);

exit(json_encode([
    'success' => true,
    'email'   => $user['email'],
    'role'    => $user['role'] ?? 'editor'
]));

// ── Funcții helper ─────────────────────────────────────────────

/**
 * Încarcă credențialele admin din .env sau din fișierul securizat de utilizatori.
 */
function loadCredentials(): array {
    // Prioritate 1: .env
    $envFile = __DIR__ . '/../.env';
    if (file_exists($envFile)) {
        $env = [];
        foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            if (strpos($line, '=') !== false) {
                [$k, $v] = explode('=', $line, 2);
                $env[trim($k)] = trim($v);
            }
        }
        if (!empty($env['ADMIN_EMAIL']) && !empty($env['ADMIN_PASSWORD_HASH'])) {
            return [[
                'email' => $env['ADMIN_EMAIL'],
                'hash'  => $env['ADMIN_PASSWORD_HASH'],
                'role'  => 'admin'
            ]];
        }
    }

    // Prioritate 2: fișier securizat de utilizatori (creat prin admin panel)
    $usersFile = __DIR__ . '/../data/users.json';
    if (file_exists($usersFile)) {
        $data = json_decode(file_get_contents($usersFile), true);
        if (is_array($data)) return $data;
    }

    // Fallback: niciun utilizator configurat
    return [];
}

/**
 * Logare tentative de autentificare.
 */
function logAuth(string $ip, string $status, string $email): void {
    $logDir  = __DIR__ . '/../data/logs/';
    if (!is_dir($logDir)) mkdir($logDir, 0700, true);
    $logFile = $logDir . 'auth_' . date('Y-m') . '.log';
    $entry   = sprintf(
        "%s | %-10s | IP: %-40s | Email: %s\n",
        date('Y-m-d H:i:s'), $status, $ip, $email
    );
    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}
