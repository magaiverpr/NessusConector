<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Config;
use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\TenableWasClient;

include('../../../inc/includes.php');

Session::checkRight(Config::$rightname, UPDATE);
Html::header_nocache();
header('Content-Type: application/json; charset=utf-8');

$provider = strtolower(trim((string) ($_POST['provider'] ?? 'nessus')));

if (!in_array($provider, ['nessus', 'was'], true)) {
    http_response_code(400);
    echo json_encode([
        'ok'      => false,
        'message' => __('Unknown provider.', 'nessusglpi'),
    ], JSON_THROW_ON_ERROR);
    return;
}

// The form never echoes the saved secret back (and the user often leaves the
// credential fields untouched), so fall back to the stored configuration for
// any blank field. This lets "Test connection" reuse the already-saved keys
// without forcing the user to retype them.
$stored = Config::getSingleton();
$input  = $_POST;

if (trim((string) ($input['api_url'] ?? '')) === '') {
    $input['api_url'] = (string) ($stored->fields['api_url'] ?? '');
}
if (trim((string) ($input['access_key'] ?? '')) === '') {
    $input['access_key'] = (string) ($stored->fields['access_key'] ?? '');
}
if (trim((string) ($input['secret_key'] ?? '')) === '') {
    $input['secret_key'] = $stored->getSecretKey();
}

$candidate = Config::createFromInput($input);
$startedAt = microtime(true);

try {
    if ($provider === 'nessus') {
        $result = (new NessusClient($candidate))->testConnection();
    } else {
        $result = (new TenableWasClient($candidate))->testConnection();
    }

    $latencyMs = (int) round((microtime(true) - $startedAt) * 1000);

    echo json_encode([
        'ok'         => true,
        'provider'   => $provider,
        'message'    => (string) ($result['message'] ?? __('Connection successful.', 'nessusglpi')),
        'latency_ms' => $latencyMs,
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    $latencyMs = (int) round((microtime(true) - $startedAt) * 1000);
    $message   = trim((string) $e->getMessage());

    if ($message === '') {
        $message = $provider === 'nessus'
            ? __('Unexpected error while testing the Nessus connection.', 'nessusglpi')
            : __('Unexpected error while testing the Tenable WAS connection.', 'nessusglpi');
    }

    http_response_code(200);
    echo json_encode([
        'ok'         => false,
        'provider'   => $provider,
        'message'    => $message,
        'latency_ms' => $latencyMs,
    ], JSON_THROW_ON_ERROR);
}
