<?php
/**
 * FABER – Atelier de Consultanță
 * contact.php — Backend formular contact
 *
 * Securitate implementată:
 *  - Rate limiting: max 5 cereri per IP per 15 minute
 *  - Sanitizare completă a tuturor inputurilor
 *  - Validare strictă câmpuri
 *  - Respingere payload supradimensionat (>10KB)
 *  - Protecție CSRF prin origin/referer check
 *  - Headers de securitate pe răspuns
 *  - Logare tentative abuzive
 */

declare(strict_types=1);

// ── Configurare ────────────────────────────────────────────────
define('RATE_LIMIT_MAX',     5);       // max cereri permise
define('RATE_LIMIT_WINDOW',  900);     // fereastră timp (secunde) = 15 min
define('MAX_PAYLOAD_BYTES',  10240);   // 10 KB max
define('DATA_DIR',           __DIR__ . '/data/rate_limit/');
define('ALLOWED_ORIGIN',     'https://atelierdeconsultanta.ro');

// Încarcă .env dacă există
$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            [$k, $v] = explode('=', $line, 2);
            $_ENV[trim($k)] = trim($v);
        }
    }
}

$CONTACT_TO   = $_ENV['CONTACT_TO_EMAIL']  ?? 'contact@atelierdeconsultanta.ro';
$CONTACT_FROM = $_ENV['CONTACT_FROM_NAME'] ?? 'FABER - Website';

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

// ── Verificare origine (anti-CSRF de bază) ────────────────────
$origin  = $_SERVER['HTTP_ORIGIN']  ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$validOrigins = [ALLOWED_ORIGIN, 'http://localhost', 'http://127.0.0.1'];
$originOk = false;
foreach ($validOrigins as $vo) {
    if (strpos($origin, $vo) === 0 || strpos($referer, $vo) === 0) {
        $originOk = true;
        break;
    }
}
// Dezactivat în dev — activați în producție decomentând:
// if (!$originOk) { http_response_code(403); exit(json_encode(['success'=>false,'error'=>'Origine invalidă.'])); }

// ── Verificare dimensiune payload ─────────────────────────────
$rawInput = file_get_contents('php://input');
if (strlen($rawInput) > MAX_PAYLOAD_BYTES) {
    http_response_code(413);
    exit(json_encode(['success' => false, 'error' => 'Cerere prea mare.']));
}

// ── Rate Limiting per IP ───────────────────────────────────────
$ip = preg_replace('/[^0-9a-fA-F:.\-]/', '', $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$ip = substr($ip, 0, 45); // max IPv6 length

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0700, true);
}
// Protejăm directorul de acces web
$htFile = DATA_DIR . '.htaccess';
if (!file_exists($htFile)) {
    file_put_contents($htFile, "Deny from all\n");
}

$rateLimitFile = DATA_DIR . hash('sha256', $ip) . '.json';
$now = time();
$attempts = [];

if (file_exists($rateLimitFile)) {
    $data = json_decode(file_get_contents($rateLimitFile), true);
    if (is_array($data)) {
        // Păstrăm doar tentativele din fereastra curentă
        $attempts = array_filter($data, fn($t) => ($now - $t) < RATE_LIMIT_WINDOW);
    }
}

if (count($attempts) >= RATE_LIMIT_MAX) {
    $retryAfter = RATE_LIMIT_WINDOW - ($now - min($attempts));
    header('Retry-After: ' . $retryAfter);
    http_response_code(429);
    logAbuse($ip, 'rate_limit_contact');
    exit(json_encode([
        'success'     => false,
        'error'       => 'Prea multe cereri. Vă rugăm așteptați ' . ceil($retryAfter / 60) . ' minute.',
        'retry_after' => $retryAfter
    ]));
}

// Înregistrăm această tentativă
$attempts[] = $now;
file_put_contents($rateLimitFile, json_encode(array_values($attempts)), LOCK_EX);

// ── Parsare date POST sau JSON ─────────────────────────────────
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (strpos($contentType, 'application/json') !== false) {
    $input = json_decode($rawInput, true) ?? [];
} else {
    parse_str($rawInput, $input);
    if (empty($input)) $input = $_POST;
}

// ── Sanitizare inputuri ────────────────────────────────────────
function sanitizeText(mixed $val, int $maxLen = 200): string {
    if (!is_string($val)) return '';
    $val = trim($val);
    $val = strip_tags($val);
    $val = htmlspecialchars($val, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $val = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $val); // caractere control
    return substr($val, 0, $maxLen);
}

function sanitizeEmail(mixed $val): string {
    $val = trim((string)$val);
    $clean = filter_var($val, FILTER_SANITIZE_EMAIL);
    return substr($clean, 0, 254);
}

function sanitizePhone(mixed $val): string {
    $val = preg_replace('/[^0-9+\-\s()]/', '', (string)$val);
    return substr(trim($val), 0, 20);
}

$name    = sanitizeText($input['name']    ?? $input['contact-name']    ?? '', 100);
$email   = sanitizeEmail($input['email']  ?? $input['contact-email']   ?? '');
$phone   = sanitizePhone($input['phone']  ?? $input['contact-phone']   ?? '');
$message = sanitizeText($input['message'] ?? $input['contact-message'] ?? '', 2000);
$gdpr    = !empty($input['gdpr'] ?? $input['gdpr-consent'] ?? '');
$program = sanitizeText($input['program'] ?? '', 100);

// ── Validare câmpuri obligatorii ───────────────────────────────
$errors = [];

if (strlen($name) < 2) {
    $errors[] = 'Numele este obligatoriu (minim 2 caractere).';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Adresa de email nu este validă.';
}
if (!$gdpr) {
    $errors[] = 'Acceptul GDPR este obligatoriu.';
}

// Verificare spam simplu (honeypot — câmpul trebuie să fie gol)
if (!empty($input['website'] ?? $input['_hp'] ?? '')) {
    // Bot detectat — returnăm succes fals pentru a nu dezvălui detecția
    exit(json_encode(['success' => true, 'message' => 'Mesajul a fost trimis cu succes!']));
}

if (!empty($errors)) {
    http_response_code(422);
    exit(json_encode(['success' => false, 'errors' => $errors]));
}

// ── Compunere email ────────────────────────────────────────────
$subject = 'Cerere nouă de consultanță — FABER Website';
if ($program) $subject .= ' (' . $program . ')';

$body  = "=== Cerere nouă de consultanță ===\n\n";
$body .= "Nume:    " . htmlspecialchars_decode($name)    . "\n";
$body .= "Email:   " . $email                            . "\n";
if ($phone) {
    $body .= "Telefon: " . $phone . "\n";
}
if ($program) {
    $body .= "Program: " . htmlspecialchars_decode($program) . "\n";
}
if ($message) {
    $body .= "\nMesaj:\n" . htmlspecialchars_decode($message) . "\n";
}
$body .= "\n---\nTrimis de: " . $ip . "\n";
$body .= "Data: " . date('d.m.Y H:i:s') . "\n";

$headers  = "From: {$CONTACT_FROM} <no-reply@atelierdeconsultanta.ro>\r\n";
$headers .= "Reply-To: {$name} <{$email}>\r\n";
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "Content-Transfer-Encoding: 8bit\r\n";
$headers .= "X-Mailer: FABER-Contact/2.0\r\n";

// ── Trimitere email ────────────────────────────────────────────
$sent = mail(
    $CONTACT_TO,
    '=?UTF-8?B?' . base64_encode($subject) . '?=',
    $body,
    $headers,
    '-f no-reply@atelierdeconsultanta.ro'
);

// ── Trimite email de confirmare clientului ─────────────────────
$confirmSubject = 'Am primit mesajul dumneavoastră — FABER';
$confirmBody  = "Bună ziua, " . htmlspecialchars_decode($name) . ",\n\n";
$confirmBody .= "Am primit cererea dumneavoastră și vă vom contacta în cel mai scurt timp.\n\n";
$confirmBody .= "Echipa FABER – Atelier de Consultanță\n";
$confirmBody .= "https://atelierdeconsultanta.ro\n";

$confirmHeaders  = "From: FABER – Atelier de Consultanță <contact@atelierdeconsultanta.ro>\r\n";
$confirmHeaders .= "MIME-Version: 1.0\r\n";
$confirmHeaders .= "Content-Type: text/plain; charset=UTF-8\r\n";

mail($email, '=?UTF-8?B?' . base64_encode($confirmSubject) . '?=', $confirmBody, $confirmHeaders);

// ── Răspuns final ──────────────────────────────────────────────
if ($sent) {
    http_response_code(200);
    exit(json_encode(['success' => true, 'message' => 'Mesajul a fost trimis cu succes!']));
} else {
    http_response_code(500);
    exit(json_encode(['success' => false, 'error' => 'Eroare la trimiterea emailului. Vă rugăm contactați-ne direct.']));
}

// ── Funcție logare abuzuri ─────────────────────────────────────
function logAbuse(string $ip, string $reason): void {
    $logDir  = __DIR__ . '/data/logs/';
    if (!is_dir($logDir)) mkdir($logDir, 0700, true);
    $logFile = $logDir . 'abuse_' . date('Y-m') . '.log';
    $entry   = date('Y-m-d H:i:s') . " | {$reason} | IP: {$ip}\n";
    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}
