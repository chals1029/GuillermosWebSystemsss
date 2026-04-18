<?php
declare(strict_types=1);

require_once __DIR__ . '/../../Controllers/Security/RequestRateLimiter.php';

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$storageFile = sys_get_temp_dir() . '/ddos_unit_' . bin2hex(random_bytes(6)) . '.json';
$limiter = new RequestRateLimiter($storageFile, 3, 10, 20);

try {
    $r1 = $limiter->check('unit-key', 1000);
    $r2 = $limiter->check('unit-key', 1001);
    $r3 = $limiter->check('unit-key', 1002);
    $r4 = $limiter->check('unit-key', 1003);
    $r5 = $limiter->check('unit-key', 1025);

    assertTrue($r1['allowed'] === true, 'First request should be allowed.');
    assertTrue($r2['allowed'] === true, 'Second request should be allowed.');
    assertTrue($r3['allowed'] === true, 'Third request should be allowed.');
    assertTrue($r3['remaining'] === 0, 'Remaining requests should be 0 at limit.');

    assertTrue($r4['allowed'] === false, 'Fourth request should be blocked.');
    assertTrue($r4['retry_after'] > 0, 'Blocked response should contain retry_after.');

    assertTrue($r5['allowed'] === true, 'Request after block expiry should be allowed.');
    assertTrue($r5['remaining'] === 2, 'Remaining should reset after unblock.');

    echo "PASS: DdosRateLimiterTest\n";
} finally {
    @unlink($storageFile);
}

