<?php
declare(strict_types=1);

require_once __DIR__ . '/RequestRateLimiter.php';

final class DdosGuard
{
    /**
     * @param array{
     *     scope?: string,
     *     max_requests?: int,
     *     window_seconds?: int,
     *     block_seconds?: int,
     *     storage_file?: string,
     *     message?: string,
     *     request_methods?: array<int, string>,
     *     response_type?: 'auto'|'json'|'redirect',
     *     redirect_url?: string,
     *     redirect_query_key?: string,
     *     exit_on_block?: bool,
     *     now?: int,
     *     server?: array<string, mixed>,
     *     session?: array<string, mixed>,
     *     get?: array<string, mixed>,
     *     post?: array<string, mixed>
     * } $options
     */
    public static function protect(array $options = []): bool
    {
        $server = $options['server'] ?? $_SERVER;
        $session = $options['session'] ?? $_SESSION ?? [];
        $get = $options['get'] ?? $_GET ?? [];
        $post = $options['post'] ?? $_POST ?? [];

        $requestMethod = strtoupper((string)($server['REQUEST_METHOD'] ?? 'GET'));
        $allowedMethods = $options['request_methods'] ?? ['GET', 'POST'];
        if (!in_array($requestMethod, $allowedMethods, true)) {
            return true;
        }

        $scope = trim((string)($options['scope'] ?? 'global'));
        if ($scope === '') {
            $scope = 'global';
        }

        $storageFile = (string)($options['storage_file'] ?? '');
        if ($storageFile === '') {
            $storageFile = self::envStringOrDefault('DDOS_RATE_LIMIT_STORAGE', __DIR__ . '/../../storage_rate_limits/ddos_rate_limits.json');
        }

        $maxRequests = (int)($options['max_requests'] ?? self::envIntOrDefault('DDOS_MAX_REQUESTS', 60));
        $windowSeconds = (int)($options['window_seconds'] ?? self::envIntOrDefault('DDOS_WINDOW_SECONDS', 60));
        $blockSeconds = (int)($options['block_seconds'] ?? self::envIntOrDefault('DDOS_BLOCK_SECONDS', 300));
        $message = (string)($options['message'] ?? 'Too many requests. Please try again shortly.');

        $now = isset($options['now']) ? (int)$options['now'] : null;

        $identityParts = [
            $scope,
            self::resolveClientIp($server),
            $requestMethod,
        ];

        $sessionUserId = (int)($session['user_id'] ?? $session['User_ID'] ?? $session['user']['user_id'] ?? $session['user']['User_ID'] ?? 0);
        if ($sessionUserId > 0) {
            $identityParts[] = 'user:' . $sessionUserId;
        }

        $key = implode('|', $identityParts);
        $limiter = new RequestRateLimiter($storageFile, $maxRequests, $windowSeconds, $blockSeconds);
        $result = $limiter->check($key, $now);

        self::sendRateLimitHeaders($result);

        if ($result['allowed']) {
            return true;
        }

        $retryAfter = max(1, (int)$result['retry_after']);
        $payload = [
            'status' => 'error',
            'message' => $message,
            'retry_after' => $retryAfter,
        ];

        $responseType = strtolower((string)($options['response_type'] ?? 'auto'));
        if ($responseType === 'auto') {
            $responseType = self::expectsJson($server, $get, $post) ? 'json' : 'redirect';
        }

        if ($responseType === 'redirect') {
            $redirectUrl = (string)($options['redirect_url'] ?? '/Views/landing/index.php');
            $queryKey = trim((string)($options['redirect_query_key'] ?? 'error'));
            if ($queryKey === '') {
                $queryKey = 'error';
            }
            $location = self::appendQuery($redirectUrl, [$queryKey => $message]);
            if (!headers_sent()) {
                header('Retry-After: ' . $retryAfter);
                header('Location: ' . $location);
            }
            http_response_code(429);
        } else {
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
                header('Retry-After: ' . $retryAfter);
            }
            http_response_code(429);
            echo json_encode($payload);
        }

        if (($options['exit_on_block'] ?? true) === true) {
            exit;
        }

        return false;
    }

    /**
     * @param array<string, mixed> $server
     */
    public static function resolveClientIp(array $server): string
    {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($candidates as $candidate) {
            $raw = trim((string)($server[$candidate] ?? ''));
            if ($raw === '') {
                continue;
            }

            if ($candidate === 'HTTP_X_FORWARDED_FOR') {
                $parts = array_map('trim', explode(',', $raw));
                foreach ($parts as $part) {
                    if (filter_var($part, FILTER_VALIDATE_IP)) {
                        return $part;
                    }
                }
                continue;
            }

            if (filter_var($raw, FILTER_VALIDATE_IP)) {
                return $raw;
            }
        }

        return 'unknown';
    }

    /**
     * @param array{limit: int, remaining: int, reset_at: int} $result
     */
    private static function sendRateLimitHeaders(array $result): void
    {
        if (headers_sent()) {
            return;
        }

        header('X-RateLimit-Limit: ' . (int)$result['limit']);
        header('X-RateLimit-Remaining: ' . max(0, (int)$result['remaining']));
        header('X-RateLimit-Reset: ' . max(0, (int)$result['reset_at']));
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $get
     * @param array<string, mixed> $post
     */
    private static function expectsJson(array $server, array $get, array $post): bool
    {
        $requestedWith = strtolower((string)($server['HTTP_X_REQUESTED_WITH'] ?? ''));
        if ($requestedWith === 'xmlhttprequest') {
            return true;
        }

        $accept = strtolower((string)($server['HTTP_ACCEPT'] ?? ''));
        if (strpos($accept, 'application/json') !== false) {
            return true;
        }

        $contentType = strtolower((string)($server['CONTENT_TYPE'] ?? ''));
        if (strpos($contentType, 'application/json') !== false) {
            return true;
        }

        return false;
    }

    /**
     * @param array<string, string> $query
     */
    private static function appendQuery(string $url, array $query): string
    {
        $separator = strpos($url, '?') === false ? '?' : '&';
        return $url . $separator . http_build_query($query);
    }

    private static function envIntOrDefault(string $name, int $default): int
    {
        $value = getenv($name);
        if ($value === false || $value === '') {
            return $default;
        }

        if (!is_numeric($value)) {
            return $default;
        }

        return (int)$value;
    }

    private static function envStringOrDefault(string $name, string $default): string
    {
        $value = getenv($name);
        if ($value === false) {
            return $default;
        }

        $trimmed = trim((string)$value);
        return $trimmed === '' ? $default : $trimmed;
    }
}
