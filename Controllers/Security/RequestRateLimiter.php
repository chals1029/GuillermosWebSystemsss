<?php
declare(strict_types=1);

/**
 * File-backed request limiter with simple fixed-window counting.
 * Uses an exclusive file lock to stay safe under concurrent requests.
 */
final class RequestRateLimiter
{
    private string $storageFile;
    private int $maxRequests;
    private int $windowSeconds;
    private int $blockSeconds;

    public function __construct(string $storageFile, int $maxRequests, int $windowSeconds, int $blockSeconds)
    {
        $this->storageFile = $storageFile;
        $this->maxRequests = max(1, $maxRequests);
        $this->windowSeconds = max(1, $windowSeconds);
        $this->blockSeconds = max(1, $blockSeconds);
    }

    /**
     * @return array{allowed: bool, limit: int, remaining: int, retry_after: int, reset_at: int}
     */
    public function check(string $key, ?int $now = null): array
    {
        $now = $now ?? time();

        try {
            return $this->withLockedState(function (array &$state) use ($key, $now): array {
                $record = $state[$key] ?? [
                    'timestamps' => [],
                    'blocked_until' => 0,
                ];

                $timestamps = array_values(array_filter(
                    (array)($record['timestamps'] ?? []),
                    static function ($timestamp) use ($now): bool {
                        return is_numeric($timestamp) && (int)$timestamp > 0 && (int)$timestamp > ($now - 3600);
                    }
                ));

                $windowStart = $now - $this->windowSeconds + 1;
                $timestamps = array_values(array_filter(
                    $timestamps,
                    static fn (int $timestamp): bool => $timestamp >= $windowStart
                ));

                $blockedUntil = (int)($record['blocked_until'] ?? 0);
                if ($blockedUntil > $now) {
                    $retryAfter = $blockedUntil - $now;
                    $state[$key] = [
                        'timestamps' => $timestamps,
                        'blocked_until' => $blockedUntil,
                    ];

                    return [
                        'allowed' => false,
                        'limit' => $this->maxRequests,
                        'remaining' => 0,
                        'retry_after' => $retryAfter,
                        'reset_at' => $blockedUntil,
                    ];
                }

                $timestamps[] = $now;
                $requestCount = count($timestamps);

                if ($requestCount > $this->maxRequests) {
                    $blockedUntil = $now + $this->blockSeconds;
                    $state[$key] = [
                        'timestamps' => [],
                        'blocked_until' => $blockedUntil,
                    ];

                    return [
                        'allowed' => false,
                        'limit' => $this->maxRequests,
                        'remaining' => 0,
                        'retry_after' => $this->blockSeconds,
                        'reset_at' => $blockedUntil,
                    ];
                }

                $resetAt = min($timestamps) + $this->windowSeconds;
                $remaining = max(0, $this->maxRequests - $requestCount);

                $state[$key] = [
                    'timestamps' => $timestamps,
                    'blocked_until' => 0,
                ];

                return [
                    'allowed' => true,
                    'limit' => $this->maxRequests,
                    'remaining' => $remaining,
                    'retry_after' => 0,
                    'reset_at' => $resetAt,
                ];
            });
        } catch (\Throwable $throwable) {
            // Fail open if limiter storage has an unexpected issue.
            return [
                'allowed' => true,
                'limit' => $this->maxRequests,
                'remaining' => $this->maxRequests,
                'retry_after' => 0,
                'reset_at' => $now + $this->windowSeconds,
            ];
        }
    }

    public function clearAll(): void
    {
        $dir = dirname($this->storageFile);
        if (!is_dir($dir)) {
            return;
        }

        @unlink($this->storageFile);
    }

    /**
     * @param callable(array): array $callback
     * @return array{allowed: bool, limit: int, remaining: int, retry_after: int, reset_at: int}
     */
    private function withLockedState(callable $callback): array
    {
        $dir = dirname($this->storageFile);
        if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new \RuntimeException('Unable to create rate limiter directory.');
        }

        $handle = @fopen($this->storageFile, 'c+');
        if ($handle === false) {
            throw new \RuntimeException('Unable to open rate limiter storage file.');
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException('Unable to lock rate limiter storage file.');
            }

            rewind($handle);
            $raw = stream_get_contents($handle);
            $state = [];
            if (is_string($raw) && trim($raw) !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    $state = $decoded;
                }
            }

            $result = $callback($state);

            rewind($handle);
            ftruncate($handle, 0);
            $encoded = json_encode($state, JSON_PRETTY_PRINT);
            if ($encoded === false) {
                throw new \RuntimeException('Unable to encode rate limiter state.');
            }
            fwrite($handle, $encoded);
            fflush($handle);
            flock($handle, LOCK_UN);

            return $result;
        } finally {
            fclose($handle);
        }
    }
}

