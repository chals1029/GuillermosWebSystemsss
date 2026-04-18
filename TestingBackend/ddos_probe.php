<?php
declare(strict_types=1);

require_once __DIR__ . '/../Controllers/Security/DdosGuard.php';

$scope = 'ddos_probe';
$maxRequests = 2;
$windowSeconds = 30;
$blockSeconds = 1;
$storageFile = '';

if (PHP_SAPI === 'cli') {
    $cli = getopt('', [
        'ip::',
        'method::',
        'store::',
        'scope::',
        'max::',
        'window::',
        'block::',
    ]);

    $_SERVER['REMOTE_ADDR'] = (string)($cli['ip'] ?? '198.51.100.10');
    $_SERVER['REQUEST_METHOD'] = strtoupper((string)($cli['method'] ?? 'POST'));
    $_SERVER['HTTP_ACCEPT'] = 'application/json';

    if (isset($cli['store'])) {
        $storageFile = (string)$cli['store'];
    }
    if (isset($cli['scope'])) {
        $scope = (string)$cli['scope'];
    }
    if (isset($cli['max']) && is_numeric($cli['max'])) {
        $maxRequests = (int)$cli['max'];
    }
    if (isset($cli['window']) && is_numeric($cli['window'])) {
        $windowSeconds = (int)$cli['window'];
    }
    if (isset($cli['block']) && is_numeric($cli['block'])) {
        $blockSeconds = (int)$cli['block'];
    }
}

$guardOptions = [
    'scope' => $scope,
    'max_requests' => $maxRequests,
    'window_seconds' => $windowSeconds,
    'block_seconds' => $blockSeconds,
    'response_type' => 'json',
    'message' => 'Too many probe requests.',
    'exit_on_block' => false,
];

if ($storageFile !== '') {
    $guardOptions['storage_file'] = $storageFile;
}

if (!DdosGuard::protect($guardOptions)) {
    exit(0);
}

if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
}
http_response_code(200);
echo json_encode([
    'status' => 'ok',
    'scope' => $scope,
]);

