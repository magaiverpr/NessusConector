<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\TenableWasClient;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, READ);
Html::header_nocache();
header('Content-Type: application/json; charset=utf-8');

$scanType = Scan::normalizeSource($_POST['scan_type'] ?? Scan::SOURCE_NESSUS);
$scanId   = trim((string) ($_POST['scan_id'] ?? ''));

if ($scanId === '') {
    http_response_code(400);
    echo json_encode([
        'ok'      => false,
        'message' => __('Provide a scan ID before checking.', 'nessusglpi'),
    ], JSON_THROW_ON_ERROR);
    return;
}

try {
    $details = $scanType === Scan::SOURCE_WAS
        ? (new TenableWasClient())->getScanDetails($scanId)
        : (new NessusClient())->getScanDetails($scanId);

    $name = nessusglpi_extract_scan_preview_name($details, $scanId, $scanType);

    $info = is_array($details['info'] ?? null) ? $details['info'] : [];
    $targets = nessusglpi_first_non_empty([
        $info['targets']         ?? null,
        $details['target']       ?? null,
        $details['targets']      ?? null,
        $details['url']          ?? null,
        $details['application_uri'] ?? null,
    ]);

    $status = nessusglpi_first_non_empty([
        $info['status']          ?? null,
        $details['status']       ?? null,
        $details['scan_status']  ?? null,
        $details['last_status']  ?? null,
    ]);

    $folder = nessusglpi_first_non_empty([
        $info['folder_name']     ?? null,
        $details['folder_name']  ?? null,
    ]);

    $owner = nessusglpi_first_non_empty([
        $info['owner']           ?? null,
        $details['owner']        ?? null,
    ]);

    $lastModification = nessusglpi_first_non_empty([
        $info['timestamp']       ?? null,
        $details['last_modification_date'] ?? null,
        $info['scan_end']        ?? null,
    ]);

    $payload = [
        'ok'   => true,
        'name' => $name,
        'meta' => array_filter([
            'targets'      => $targets,
            'status'       => $status,
            'folder'       => $folder,
            'owner'        => $owner,
            'last_updated' => is_numeric($lastModification)
                ? date('Y-m-d H:i', (int) $lastModification)
                : (string) $lastModification,
        ], static fn ($v) => trim((string) $v) !== ''),
    ];

    echo json_encode($payload, JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(200);
    echo json_encode([
        'ok'      => false,
        'message' => $e->getMessage() !== ''
            ? $e->getMessage()
            : __('Could not retrieve scan details.', 'nessusglpi'),
    ], JSON_THROW_ON_ERROR);
}

function nessusglpi_extract_scan_preview_name(array $details, string $scanId, string $scanType): string
{
    $candidates = [
        $details['info']['name']    ?? null,
        $details['name']            ?? null,
        $details['scan_name']       ?? null,
        $details['config_name']     ?? null,
        $details['application_name'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (is_scalar($candidate) && trim((string) $candidate) !== '') {
            return trim((string) $candidate);
        }
    }

    return $scanType === Scan::SOURCE_WAS
        ? sprintf(__('WAS scan %s', 'nessusglpi'), $scanId)
        : sprintf(__('Scan %s', 'nessusglpi'), $scanId);
}

function nessusglpi_first_non_empty(array $values): string
{
    foreach ($values as $value) {
        if (is_array($value)) {
            $value = implode(', ', array_filter(array_map('strval', $value), static fn ($v) => trim($v) !== ''));
        }
        $text = trim((string) $value);
        if ($text !== '' && $text !== '0') {
            return $text;
        }
    }

    return '';
}
