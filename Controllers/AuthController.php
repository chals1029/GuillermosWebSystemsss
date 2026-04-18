<?php
session_start(); // Start session at the very top

// Import PHPMailer classes into the global namespace
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Handles registration and login actions
require_once __DIR__ . '/../vendor/autoload.php'; // Composer's autoloader for PHPMailer
require_once __DIR__ . '/../Config.php';
require_once __DIR__ . '/../Models/User.php';
require_once __DIR__ . '/EmailApiController.php'; // Use the new Email API controller
require_once __DIR__ . '/PasswordPolicy.php';
require_once __DIR__ . '/Security/DdosGuard.php';

if (!DdosGuard::protect([
    'scope' => 'auth',
    'max_requests' => (int)(getenv('AUTH_DDOS_MAX_REQUESTS') ?: 20),
    'window_seconds' => (int)(getenv('AUTH_DDOS_WINDOW_SECONDS') ?: 60),
    'block_seconds' => (int)(getenv('AUTH_DDOS_BLOCK_SECONDS') ?: 600),
    'request_methods' => ['POST'],
    'response_type' => 'auto',
    'redirect_url' => '/Views/landing/index.php',
    'message' => 'Too many authentication requests. Please try again in a few minutes.',
    'exit_on_block' => false,
])) {
    exit;
}

$userModel = new User($conn);

$action = $_GET['action'] ?? $_POST['action'] ?? '';

const LOGIN_ATTEMPTS_FILE = __DIR__ . '/../storage/login_attempts.json';
const LOGIN_ATTEMPTS_SESSION_KEY = 'login_attempts_fallback';
const PASSWORD_RESET_RESEND_COOLDOWN_SECONDS = 300;
const PASSWORD_RESET_CODE_TTL_SECONDS = 300;
const SQLI_BLOCK_MESSAGE = 'Bro Imagine trying Sql injection in big 2026 💔';

function isSuspiciousSqlInput(string $value): bool
{
    $v = strtolower(trim($value));
    if ($v === '') {
        return false;
    }

    // Heuristic guard for obvious SQLi payloads. Prepared statements are still the main defense.
    $patterns = [
        '/\b\d+\s*=\s*\d+\b/i',
        '/\b(or|and)\b\s+\d+\s*=\s*\d+/i',
        '/[\'\"]\s*(or|and)\s+[\'\"]?[^\'\"]+/i',
        '/\bunion\b\s+\bselect\b/i',
        '/\bselect\b.+\bfrom\b/i',
        '/\binformation_schema\b/i',
        '/\bdrop\b\s+\btable\b/i',
        '/\binsert\b\s+\binto\b/i',
        '/\bdelete\b\s+\bfrom\b/i',
        '/\bupdate\b\s+\w+\s+\bset\b/i',
        '/--/',
        '/\/\*/',
        '/\*\//',
        '/#/',
        '/\bxp_cmdshell\b/i',
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $v) === 1) {
            return true;
        }
    }

    return false;
}

function requestHasSuspiciousSqlInput(array $inputs): bool
{
    foreach ($inputs as $input) {
        if (is_string($input) && isSuspiciousSqlInput($input)) {
            return true;
        }
    }

    return false;
}

function hasBlockedLoginWording(string $identity): bool
{
    $normalized = normalizeLoginIdentity($identity);
    return $normalized === 'admin';
}

function normalizeLoginIdentity(string $identity): string
{
    return strtolower(trim($identity));
}

function getLoginAttemptKey(string $identity): string
{
    return normalizeLoginIdentity($identity);
}

function loadLoginAttempts(): array
{
    if (is_file(LOGIN_ATTEMPTS_FILE)) {
        $json = file_get_contents(LOGIN_ATTEMPTS_FILE);
        if ($json !== false && trim($json) !== '') {
            $decoded = json_decode($json, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }
    }

    if (isset($_SESSION[LOGIN_ATTEMPTS_SESSION_KEY]) && is_array($_SESSION[LOGIN_ATTEMPTS_SESSION_KEY])) {
        return $_SESSION[LOGIN_ATTEMPTS_SESSION_KEY];
    }

    return [];
}

function saveLoginAttempts(array $attempts): void
{
    $dir = dirname(LOGIN_ATTEMPTS_FILE);
    if (!is_dir($dir)) {
        // Avoid warning noise in concurrent requests where another process creates the directory first.
        if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
            $_SESSION[LOGIN_ATTEMPTS_SESSION_KEY] = $attempts;
            return;
        }
    }

    if (!is_writable($dir)) {
        $_SESSION[LOGIN_ATTEMPTS_SESSION_KEY] = $attempts;
        return;
    }

    $savedToFile = false;
    $encoded = json_encode($attempts, JSON_PRETTY_PRINT);
    if ($encoded !== false) {
        $written = @file_put_contents(LOGIN_ATTEMPTS_FILE, $encoded, LOCK_EX);
        $savedToFile = ($written !== false);
    }

    // Keep a session fallback copy so counters still work if filesystem writes fail.
    if (!$savedToFile) {
        $_SESSION[LOGIN_ATTEMPTS_SESSION_KEY] = $attempts;
    } else {
        unset($_SESSION[LOGIN_ATTEMPTS_SESSION_KEY]);
    }
}

function getLoginLockStatus(string $identity): array
{
    $attempts = loadLoginAttempts();
    $key = getLoginAttemptKey($identity);
    $now = time();

    if (!isset($attempts[$key])) {
        return [
            'locked' => false,
            'seconds_remaining' => 0,
            'message' => '',
        ];
    }

    $record = $attempts[$key];
    $lockedUntil = (int)($record['locked_until'] ?? 0);

    if ($lockedUntil <= $now) {
        return [
            'locked' => false,
            'seconds_remaining' => 0,
            'message' => '',
        ];
    }

    $secondsRemaining = $lockedUntil - $now;
    $minutesRemaining = (int)ceil($secondsRemaining / 60);
    $lastLockMinutes = (int)($record['last_lock_minutes'] ?? 5);

    if ($lastLockMinutes >= 30) {
        $message = 'Too many failed attempts. Please click Forgot Password and try again after 30 minutes. Time remaining: ' . $minutesRemaining . ' minute(s).';
    } else {
        $message = 'Too many failed attempts. Please try again after 5 minutes. Time remaining: ' . $minutesRemaining . ' minute(s).';
    }

    return [
        'locked' => true,
        'seconds_remaining' => $secondsRemaining,
        'message' => $message,
    ];
}

function registerFailedLoginAttempt(string $identity): array
{
    $attempts = loadLoginAttempts();
    $key = getLoginAttemptKey($identity);
    $now = time();

    $record = $attempts[$key] ?? [
        'failed_attempts' => 0,
        'lock_stage' => 0,
        'locked_until' => 0,
        'last_lock_minutes' => 0,
        'last_failed_at' => 0,
    ];

    $lockedUntil = (int)($record['locked_until'] ?? 0);
    if ($lockedUntil > $now) {
        $minutesRemaining = (int)ceil(($lockedUntil - $now) / 60);
        $lastLockMinutes = (int)($record['last_lock_minutes'] ?? 5);
        if ($lastLockMinutes >= 30) {
            $message = 'Too many failed attempts. Please click Forgot Password and try again after 30 minutes. Time remaining: ' . $minutesRemaining . ' minute(s).';
        } else {
            $message = 'Too many failed attempts. Please try again after 5 minutes. Time remaining: ' . $minutesRemaining . ' minute(s).';
        }

        return [
            'locked' => true,
            'message' => $message,
        ];
    }

    $record['failed_attempts'] = (int)($record['failed_attempts'] ?? 0) + 1;
    $record['last_failed_at'] = $now;

    if ($record['failed_attempts'] >= 5) {
        $currentStage = (int)($record['lock_stage'] ?? 0);
        $lockMinutes = $currentStage <= 0 ? 5 : 30;

        $record['lock_stage'] = $currentStage + 1;
        $record['failed_attempts'] = 0;
        $record['last_lock_minutes'] = $lockMinutes;
        $record['locked_until'] = $now + ($lockMinutes * 60);
        $attempts[$key] = $record;
        saveLoginAttempts($attempts);

        if ($lockMinutes >= 30) {
            return [
                'locked' => true,
                'message' => 'Too many failed attempts. Please click Forgot Password and try again after 30 minutes.',
            ];
        }

        return [
            'locked' => true,
            'message' => 'Too many failed attempts. Please try again after 5 minutes.',
        ];
    }

    $attempts[$key] = $record;
    saveLoginAttempts($attempts);

    $remaining = max(0, 5 - (int)$record['failed_attempts']);
    return [
        'locked' => false,
        'message' => 'Invalid credentials. Please try again. ' . $remaining . ' attempt(s) remaining before temporary lock.',
    ];
}

function clearLoginAttemptState(string $identity): void
{
    $attempts = loadLoginAttempts();
    $key = getLoginAttemptKey($identity);
    if (isset($attempts[$key])) {
        unset($attempts[$key]);
        saveLoginAttempts($attempts);
    }
}

function isAjaxRequest(): bool
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function jsonResponse(array $payload, int $statusCode = 200): void
{
    header('Content-Type: application/json');
    http_response_code($statusCode);
    echo json_encode($payload);
    exit;
}

function appBasePath(): string
{
    if (defined('APP_BASE_PATH') && APP_BASE_PATH !== '') {
        return APP_BASE_PATH;
    }
    $scriptDir = dirname($_SERVER['PHP_SELF'] ?? '') ?: '';
    $base = preg_replace('#/Controllers/?$#', '', $scriptDir);
    if ($base === null || $base === false) {
        $base = '';
    }
    $base = rtrim($base, '/');
    return $base === '' ? '' : $base;
}

function buildUrl(string $relativePath, array $query = []): string
{
    $url = appBasePath() . $relativePath;
    if (!empty($query)) {
        $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);
    }
    return $url;
}

function redirectTo(string $relativePath, array $query = []): void
{
    header('Location: ' . buildUrl($relativePath, $query));
    exit;
}

if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phonenumber = trim($_POST['phonenumber'] ?? '');

    if (requestHasSuspiciousSqlInput([$username, $name, $email, $phonenumber])) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => SQLI_BLOCK_MESSAGE,
            ], 400);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => SQLI_BLOCK_MESSAGE,
        ]);
    }

    $errors = [];
    if (empty($username)) $errors[] = 'Username is required';
    if (empty($password)) $errors[] = 'Password is required';
    if (!empty($password) && !passwordPolicyIsStrong($password)) {
        $errors[] = passwordPolicyErrorMessage();
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'A valid email is required';
    }

    if (!empty($errors)) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => implode(' ', $errors),
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => implode(', ', $errors),
        ]);
    }

    if ($userModel->existsByUsernameOrEmail($username, $email)) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Username or email already exists',
            ], 409);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Username or email already exists',
        ]);
    }

    // Generate verification code and store user data in session
    $verification_code = substr(number_format(time() * rand(), 0, '', ''), 0, 6);
    $_SESSION['registration_data'] = [
        'username' => $username,
        'passwordHash' => password_hash($password, PASSWORD_DEFAULT),
        'name' => $name,
        'email' => $email,
        'phonenumber' => $phonenumber === '' ? null : $phonenumber,
        'user_role' => 'customer',
        'verification_code' => $verification_code,
        'timestamp' => time() // To check for expiration
    ];

    // --- Send Email using the EmailApiController ---
    $emailResult = EmailApiController::sendVerificationEmail($email, $name, $verification_code);

    if ($emailResult === true) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'success',
                'email' => $email,
                'message' => 'Verification code sent to ' . $email . '.',
            ]);
        }

        // Redirect to verification page on success
        redirectTo('/Views/landing/verify.php', [
            'email' => $email,
        ]);
    } else {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => is_string($emailResult) ? $emailResult : 'Failed to send verification email.',
            ], 500);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Unable to send verification email. Please try again later.',
        ]);
    }
}

if ($action === 'verify-email' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted_code = trim($_POST['verification_code'] ?? '');
    $email = trim($_POST['email'] ?? '');

    if (empty($submitted_code) || empty($email)) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Verification code is required.',
            ], 422);
        }

        redirectTo('/Views/landing/verify.php', [
            'error' => 'Verification code is required.',
        ]);
    }

    // Check if session data exists and is not expired (e.g., 10 minutes)
    if (!isset($_SESSION['registration_data']) || $_SESSION['registration_data']['email'] !== $email) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Verification session not found. Please register again.',
            ], 409);
        }

        redirectTo('/Views/landing/verify.php', [
            'error' => 'Verification session not found. Please register again.',
        ]);
    }

    if (time() - $_SESSION['registration_data']['timestamp'] > 600) { // 10 minutes
        unset($_SESSION['registration_data']);
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Verification code has expired. Please register again.',
            ], 410);
        }

        redirectTo('/Views/landing/verify.php', [
            'error' => 'Verification code has expired. Please register again.',
        ]);
    }

    if ($_SESSION['registration_data']['verification_code'] !== $submitted_code) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Invalid verification code.',
            ], 422);
        }

        redirectTo('/Views/landing/verify.php', [
            'email' => $email,
            'error' => 'Invalid verification code.',
        ]);
    }

    // --- Verification successful, create user ---
    $data = $_SESSION['registration_data'];
    $created = $userModel->create($data);

    unset($_SESSION['registration_data']); // Clean up session

    if ($created) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'success',
                'message' => 'Account verified successfully.',
            ]);
        }

        redirectTo('/Views/landing/index.php', [
            'registered' => 1,
        ]);
    } else {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Failed to create account after verification.',
            ], 500);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Failed to create account after verification.',
        ]);
    }
}

if ($action === 'resend-code' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_SESSION['registration_data'])) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'No pending registration found. Please start again.',
            ], 410);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'No pending registration found. Please register again.',
        ]);
    }

    $email = $_SESSION['registration_data']['email'];
    $name = $_SESSION['registration_data']['name'] ?? 'Customer';

    // Optional email check if provided to avoid tampering
    if (!empty($_POST['email']) && trim($_POST['email']) !== $email) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Email mismatch. Please register again.',
            ], 409);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Email mismatch. Please register again.',
        ]);
    }

    $verification_code = substr(number_format(time() * rand(), 0, '', ''), 0, 6);
    $_SESSION['registration_data']['verification_code'] = $verification_code;
    $_SESSION['registration_data']['timestamp'] = time();

    $emailResult = EmailApiController::sendVerificationEmail($email, $name, $verification_code);

    if ($emailResult === true) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'success',
                'message' => 'A new verification code has been sent.',
            ]);
        }

        redirectTo('/Views/landing/verify.php', [
            'email' => $email,
            'resent' => 1,
        ]);
    }

    if (isAjaxRequest()) {
        jsonResponse([
            'status' => 'error',
            'message' => is_string($emailResult) ? $emailResult : 'Unable to resend verification email.',
        ], 500);
    }

    redirectTo('/Views/landing/index.php', [
        'error' => 'Unable to resend verification email. Please try again later.',
    ]);
}

if ($action === 'forgot-password' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if (requestHasSuspiciousSqlInput([$email])) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => SQLI_BLOCK_MESSAGE,
            ], 400);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => SQLI_BLOCK_MESSAGE,
        ]);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Please provide a valid email address.',
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Please provide a valid email address.',
        ]);
    }

    $user = $userModel->findByEmail($email);
    if (!$user) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'No account found with that email address.',
            ], 404);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'No account found with that email address.',
        ]);
    }

    if (isset($_SESSION['password_reset'])
        && is_array($_SESSION['password_reset'])
        && ($_SESSION['password_reset']['email'] ?? '') === $email
    ) {
        $lastSentAt = (int)($_SESSION['password_reset']['timestamp'] ?? 0);
        $secondsSinceLastSend = time() - $lastSentAt;
        if ($lastSentAt > 0 && $secondsSinceLastSend < PASSWORD_RESET_RESEND_COOLDOWN_SECONDS) {
            $remainingSeconds = PASSWORD_RESET_RESEND_COOLDOWN_SECONDS - $secondsSinceLastSend;
            $remainingMinutes = (int)ceil($remainingSeconds / 60);
            $waitMessage = 'A reset code was already sent. Please wait ' . $remainingMinutes . ' minute(s) before requesting another code.';

            if (isAjaxRequest()) {
                jsonResponse([
                    'status' => 'success',
                    'email' => $email,
                    'proceed_to_reset' => true,
                    'message' => $waitMessage . ' You can still use the previous code.',
                ]);
            }

            redirectTo('/Views/landing/index.php', [
                'notice' => $waitMessage,
            ]);
        }
    }

    $resetCode = substr(number_format(time() * rand(), 0, '', ''), 0, 6);
    $_SESSION['password_reset'] = [
        'user_id' => $user['user_id'],
        'email' => $email,
        'code' => $resetCode,
        'timestamp' => time(),
    ];

    $emailResult = EmailApiController::sendPasswordResetEmail($email, $user['name'] ?? $user['username'] ?? 'Customer', $resetCode);

    if ($emailResult !== true) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => is_string($emailResult) ? $emailResult : 'Unable to send reset code. Please try again later.',
            ], 500);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Unable to send reset code. Please try again later.',
        ]);
    }

    if (isAjaxRequest()) {
        jsonResponse([
            'status' => 'success',
            'message' => 'A reset code has been sent to your email address.',
            'email' => $email,
        ]);
    }

    redirectTo('/Views/landing/index.php', [
        'notice' => 'A reset code has been sent to your email address.',
    ]);
}

if ($action === 'reset-password' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $code = trim($_POST['reset_code'] ?? '');
    $newPassword = $_POST['new_password'] ?? '';

    if (requestHasSuspiciousSqlInput([$email, $code])) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => SQLI_BLOCK_MESSAGE,
            ], 400);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => SQLI_BLOCK_MESSAGE,
        ]);
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $code === '' || $newPassword === '') {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Incomplete reset information.',
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Incomplete reset information.',
        ]);
    }

    if (!isset($_SESSION['password_reset']) || $_SESSION['password_reset']['email'] !== $email) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Reset session not found. Please start over.',
            ], 409);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Reset session not found. Please start over.',
        ]);
    }

    $resetData = $_SESSION['password_reset'];
    if (time() - $resetData['timestamp'] > PASSWORD_RESET_CODE_TTL_SECONDS) {
        unset($_SESSION['password_reset']);
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Reset code has expired. Please request a new one.',
            ], 410);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Reset code has expired. Please request a new one.',
        ]);
    }

    if ($resetData['code'] !== $code) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Invalid reset code. Please try again.',
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Invalid reset code. Please try again.',
        ]);
    }

    if (strlen($newPassword) < 6) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Password must be at least 6 characters long.',
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Password must be at least 6 characters long.',
        ]);
    }

    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
    $updated = $userModel->updatePassword((int)$resetData['user_id'], $passwordHash);

    unset($_SESSION['password_reset']);

    if (!$updated) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Unable to update password. Please try again.',
            ], 500);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Unable to update password. Please try again.',
        ]);
    }

    if (isAjaxRequest()) {
        jsonResponse([
            'status' => 'success',
            'message' => 'Password updated successfully. You can now log in.',
        ]);
    }

    redirectTo('/Views/landing/index.php', [
        'reset' => 1,
    ]);
}

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $identity = trim($_POST['identity'] ?? '');
    $password = $_POST['password'] ?? '';

    if (hasBlockedLoginWording($identity)) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => SQLI_BLOCK_MESSAGE,
            ], 400);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => SQLI_BLOCK_MESSAGE,
        ]);
    }

    if (requestHasSuspiciousSqlInput([$identity, $password])) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => SQLI_BLOCK_MESSAGE,
            ], 400);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => SQLI_BLOCK_MESSAGE,
        ]);
    }

    if ($identity === '' || $password === '') {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => 'Please provide both email/username and password.',
            ], 422);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => 'Missing credentials',
        ]);
    }

    $lockStatus = getLoginLockStatus($identity);
    if ($lockStatus['locked']) {
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => $lockStatus['message'],
            ], 423);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => $lockStatus['message'],
        ]);
    }

    $user = $userModel->findByUsernameOrEmail($identity);
    if (!$user || !password_verify($password, $user['password'])) {
        $attemptStatus = registerFailedLoginAttempt($identity);
        if (isAjaxRequest()) {
            jsonResponse([
                'status' => 'error',
                'message' => $attemptStatus['message'],
            ], $attemptStatus['locked'] ? 423 : 401);
        }

        redirectTo('/Views/landing/index.php', [
            'error' => $attemptStatus['message'],
        ]);
    }

    clearLoginAttemptState($identity);

    // Simple session login
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['user_role'] = $user['user_role'];
    $_SESSION['user'] = [
        'user_id' => $user['user_id'],
        'Username' => $user['username'],
        'Name' => $user['name'],
        'Email' => $user['email'],
        'Phonenumber' => $user['phonenumber'],
        'user_role' => $user['user_role']
    ];

    $role = strtolower($user['user_role'] ?? '');
    $relativeDestination = '/';
    switch ($role) {
        case 'customer':
            $relativeDestination = '/Views/customer_dashboard/Customer.php';
            break;
        case 'staff':
            $relativeDestination = '/Views/staff_dashboard/staff.php';
            break;
        case 'owner':
        case 'admin':
            $relativeDestination = '/Views/owner_dashboard/Owner.php';
            break;
        default:
            $relativeDestination = '/';
            break;
    }
    $destination = appBasePath() . $relativeDestination;

    if (isAjaxRequest()) {
        jsonResponse([
            'status' => 'success',
            'redirect' => $destination,
        ]);
    }

    header('Location: ' . $destination);
    exit;
}

// Unknown action -> redirect
redirectTo('/');
