<?php
declare(strict_types=1);

function assertTrue(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

/**
 * @return array<string, mixed>
 */
function runProbe(string $probePath, string $ip, string $storeFile, string $scope): array
{
    $args = [
        PHP_BINARY,
        $probePath,
        '--ip=' . $ip,
        '--method=POST',
        '--store=' . $storeFile,
        '--scope=' . $scope,
        '--max=2',
        '--window=30',
        '--block=1',
    ];

    $command = implode(' ', array_map('escapeshellarg', $args));
    $output = [];
    $exitCode = 1;
    exec($command, $output, $exitCode);

    if ($exitCode !== 0) {
        throw new RuntimeException('Probe command failed: ' . implode("\n", $output));
    }

    $json = trim(implode("\n", $output));
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Probe output was not valid JSON: ' . $json);
    }

    return $decoded;
}

$probePath = realpath(__DIR__ . '/../../TestingBackend/ddos_probe.php');
if ($probePath === false) {
    throw new RuntimeException('Unable to locate ddos probe endpoint.');
}

$storeFile = sys_get_temp_dir() . '/ddos_system_' . bin2hex(random_bytes(6)) . '.json';
$scope = 'ddos-system-' . bin2hex(random_bytes(4));
$ip = '203.0.113.50';

try {
    $first = runProbe($probePath, $ip, $storeFile, $scope);
    $second = runProbe($probePath, $ip, $storeFile, $scope);
    $third = runProbe($probePath, $ip, $storeFile, $scope);

    assertTrue(($first['status'] ?? '') === 'ok', 'First request should pass.');
    assertTrue(($second['status'] ?? '') === 'ok', 'Second request should pass.');
    assertTrue(($third['status'] ?? '') === 'error', 'Third request should be blocked.');
    assertTrue((int)($third['retry_after'] ?? 0) >= 1, 'Blocked response should include retry_after.');

    sleep(2);
    $afterCooldown = runProbe($probePath, $ip, $storeFile, $scope);
    assertTrue(($afterCooldown['status'] ?? '') === 'ok', 'Request should pass after cooldown.');

    echo "PASS: DdosGuardSystemTest\n";
} finally {
    @unlink($storeFile);
}

