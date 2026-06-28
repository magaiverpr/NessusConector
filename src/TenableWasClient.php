<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use RuntimeException;
use Throwable;

class TenableWasClient
{
    private Config $config;

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? Config::getSingleton();
    }

    public function testConnection(): array
    {
        // Step 1: verify credentials via /server/status (shared endpoint with VM)
        $status = $this->request('GET', '/server/status');
        $serverStatus = (string) ($status['status'] ?? 'unknown');

        // Step 2: attempt WAS-specific endpoint — may fail if account lacks WAS Config role
        try {
            $wasResponse = $this->searchScanConfigs(1);
            $items = $this->extractItems($wasResponse, ['items', 'configs', 'data', 'results']);
            return [
                'status'  => 'ok',
                'message' => sprintf(
                    __('Connection successful. Nessus status: %s. WAS: %d config(s) accessible.', 'nessusglpi'),
                    $serverStatus,
                    count($items)
                ),
                'data' => $wasResponse,
            ];
        } catch (RuntimeException $e) {
            // Credentials are valid but WAS Config role is missing.
            // Scan import via /was/v2/scans/{id} may still work fine.
            return [
                'status'  => 'ok',
                'message' => sprintf(
                    __('Connection successful. Nessus status: %s. WAS config access restricted — scan import may still work.', 'nessusglpi'),
                    $serverStatus
                ),
                'data' => $status,
            ];
        }
    }

    public function searchScanConfigs(int $limit = 200, int $offset = 0): array
    {
        return $this->request('POST', '/was/v2/configs/search?limit=' . max(1, min(200, $limit)) . '&offset=' . max(0, $offset), []);
    }

    public function getAllScanConfigs(): array
    {
        $limit = 200;
        $offset = 0;
        $all = [];

        do {
            $response = $this->searchScanConfigs($limit, $offset);
            $items = $this->extractItems($response, ['items', 'configs', 'data', 'results']);

            foreach ($items as $item) {
                if (is_array($item)) {
                    $all[] = $item;
                }
            }

            $count = count($items);
            $offset += $limit;
        } while ($count === $limit && $offset <= 10000);

        return $all;
    }

    public function searchConfigScans(string $configId, int $limit = 200, int $offset = 0): array
    {
        return $this->request(
            'POST',
            '/was/v2/configs/' . rawurlencode($configId) . '/scans/search?limit=' . max(1, min(200, $limit)) . '&offset=' . max(0, $offset),
            []
        );
    }

    public function getAllConfigScans(string $configId): array
    {
        $limit = 200;
        $offset = 0;
        $all = [];

        do {
            $response = $this->searchConfigScans($configId, $limit, $offset);
            $items = $this->extractItems($response, ['items', 'scans', 'data', 'results']);

            foreach ($items as $item) {
                if (is_array($item)) {
                    $all[] = $item;
                }
            }

            $count = count($items);
            $offset += $limit;
        } while ($count === $limit && $offset <= 10000);

        return $all;
    }

    public function getScanDetails(string $scanId): array
    {
        return $this->request('GET', '/was/v2/scans/' . rawurlencode($scanId));
    }

    public function searchScanVulnerabilities(string $scanId, int $limit = 200, int $offset = 0): array
    {
        return $this->request(
            'POST',
            '/was/v2/scans/' . rawurlencode($scanId) . '/vulnerabilities/search?limit=' . max(1, min(200, $limit)) . '&offset=' . max(0, $offset),
            []
        );
    }

    public function getAllScanVulnerabilities(string $scanId): array
    {
        $limit = 200;
        $offset = 0;
        $all = [];

        do {
            $response = $this->searchScanVulnerabilities($scanId, $limit, $offset);
            $items = $this->extractItems($response, ['items', 'vulnerabilities', 'data', 'results']);

            foreach ($items as $item) {
                if (is_array($item)) {
                    $all[] = $item;
                }
            }

            $count = count($items);
            $offset += $limit;
        } while ($count === $limit && $offset <= 10000);

        return $all;
    }

    public function getVulnerabilityDetails(string $vulnerabilityId): array
    {
        return $this->request('GET', '/was/v2/vulnerabilities/' . rawurlencode($vulnerabilityId));
    }

    private function extractItems(array $response, array $keys): array
    {
        foreach ($keys as $key) {
            if (isset($response[$key]) && is_array($response[$key])) {
                return array_values(array_filter($response[$key], 'is_array'));
            }
        }

        foreach (['data', 'response', 'result'] as $containerKey) {
            if (!isset($response[$containerKey]) || !is_array($response[$containerKey])) {
                continue;
            }

            foreach ($keys as $key) {
                if (isset($response[$containerKey][$key]) && is_array($response[$containerKey][$key])) {
                    return array_values(array_filter($response[$containerKey][$key], 'is_array'));
                }
            }
        }

        if (array_is_list($response)) {
            return array_values(array_filter($response, 'is_array'));
        }

        return [];
    }

    private function request(string $method, string $path, ?array $body = null): array
    {
        $baseUrl = trim((string) ($this->config->fields['api_url'] ?? ''));
        $accessKey = trim((string) ($this->config->fields['access_key'] ?? ''));
        $secretKey = trim($this->config->getSecretKey());
        $timeout = max(1, (int) ($this->config->fields['timeout'] ?? 30));

        if ($baseUrl === '') {
            throw new RuntimeException(__('Tenable API URL is not configured.', 'nessusglpi'));
        }

        if (!$this->isValidBaseUrl($baseUrl)) {
            throw new RuntimeException(__('Invalid Tenable API URL. Use something like https://cloud.tenable.com', 'nessusglpi'));
        }

        if ($accessKey === '' || $secretKey === '') {
            throw new RuntimeException(__('Access key and secret key are required.', 'nessusglpi'));
        }

        if (!function_exists('curl_init')) {
            throw new RuntimeException(__('The PHP cURL extension is required.', 'nessusglpi'));
        }

        $url = rtrim($baseUrl, '/') . '/' . ltrim($path, '/');
        $headers = [
            'Accept: application/json',
            'X-ApiKeys: accessKey=' . $accessKey . '; secretKey=' . $secretKey,
        ];

        set_error_handler(static function (int $severity, string $message): never {
            throw new RuntimeException($message);
        });

        try {
            $ch = curl_init($url);
            if ($ch === false) {
                throw new RuntimeException(__('Unable to initialize the cURL session.', 'nessusglpi'));
            }

            $options = [
                CURLOPT_CUSTOMREQUEST  => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => min($timeout, 10),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ];

            if ($body !== null) {
                $headers[] = 'Content-Type: application/json';
                $options[CURLOPT_HTTPHEADER] = $headers;
                $options[CURLOPT_POSTFIELDS] = $body === []
                    ? '{}'
                    : json_encode($body, JSON_THROW_ON_ERROR);
            }

            curl_setopt_array($ch, $options);

            $rawBody = curl_exec($ch);
            if ($rawBody === false) {
                $error = curl_error($ch);
                throw new RuntimeException($this->humanizeCurlError($error));
            }

            $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        } catch (Throwable $e) {
            throw new RuntimeException($this->humanizeRuntimeError($e->getMessage()), 0, $e);
        } finally {
            restore_error_handler();
        }

        $decoded = json_decode((string) $rawBody, true);
        if (!is_array($decoded)) {
            if ($statusCode === 0) {
                throw new RuntimeException(__('No valid response was received from Tenable WAS.', 'nessusglpi'));
            }

            throw new RuntimeException(__('Tenable WAS API returned an invalid JSON response.', 'nessusglpi'));
        }

        if ($statusCode >= 400) {
            $message = (string) ($decoded['error'] ?? $decoded['message'] ?? $decoded['detail'] ?? ('HTTP ' . $statusCode));
            throw new RuntimeException($message);
        }

        return $decoded;
    }

    private function isValidBaseUrl(string $baseUrl): bool
    {
        if (!filter_var($baseUrl, FILTER_VALIDATE_URL)) {
            return false;
        }

        $parts = parse_url($baseUrl);
        if (!is_array($parts)) {
            return false;
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');

        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return false;
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if (str_starts_with($host, '127.') || str_starts_with($host, '169.254.') || $host === '::1') {
                return false;
            }
        }

        return true;
    }

    private function humanizeCurlError(string $error): string
    {
        $normalized = trim($error);
        $lower = strtolower($normalized);

        if ($normalized === '') {
            return __('Unknown connection error while contacting Tenable WAS.', 'nessusglpi');
        }

        if (str_contains($lower, 'could not resolve host')) {
            return __('Unable to resolve the Tenable host name. Check the URL.', 'nessusglpi');
        }

        if (str_contains($lower, 'failed to connect')) {
            return __('Unable to connect to Tenable. Check the URL, port and firewall.', 'nessusglpi');
        }

        if (str_contains($lower, 'timed out')) {
            return __('Connection to Tenable WAS timed out.', 'nessusglpi');
        }

        if (str_contains($lower, 'ssl')) {
            return __('SSL error while connecting to Tenable WAS.', 'nessusglpi');
        }

        return $normalized;
    }

    private function humanizeRuntimeError(string $message): string
    {
        $normalized = trim($message);
        $lower = strtolower($normalized);

        if (str_contains($lower, 'contains control characters')) {
            return __('Invalid Tenable API URL. Check for spaces or invalid characters.', 'nessusglpi');
        }

        if (str_contains($lower, 'must be a string') || str_contains($lower, 'must not contain')) {
            return __('Invalid Tenable API URL.', 'nessusglpi');
        }

        return $normalized === ''
            ? __('Unexpected error while contacting Tenable WAS.', 'nessusglpi')
            : $normalized;
    }
}
