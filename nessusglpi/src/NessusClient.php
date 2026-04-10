<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use RuntimeException;
use Throwable;

class NessusClient
{
    private Config $config;

    public function __construct(?Config $config = null)
    {
        $this->config = $config ?? Config::getSingleton();
    }

    public function testConnection(): array
    {
        $response = $this->request('GET', '/server/status');

        return [
            'status'  => 'ok',
            'message' => sprintf(
                __('Connection successful. Nessus status: %s', 'nessusglpi'),
                (string) ($response['status'] ?? 'unknown')
            ),
            'data'    => $response,
        ];
    }

    public function getScanDetails(string $scanId): array
    {
        return $this->request('GET', '/scans/' . rawurlencode($scanId));
    }

    public function getScanHosts(string $scanId): array
    {
        $data = $this->getScanDetails($scanId);
        return is_array($data['hosts'] ?? null) ? $data['hosts'] : [];
    }

    public function getScanHostDetails(string $scanId, string $hostId): array
    {
        return $this->request('GET', '/scans/' . rawurlencode($scanId) . '/hosts/' . rawurlencode($hostId));
    }

    public function getScanHostPluginDetails(string $scanId, string $hostId, string $pluginId): array
    {
        return $this->request(
            'GET',
            '/scans/' . rawurlencode($scanId) . '/hosts/' . rawurlencode($hostId) . '/plugins/' . rawurlencode($pluginId)
        );
    }

    public function getHostVulnerabilities(string $scanId, string $hostId): array
    {
        $data = $this->getScanHostDetails($scanId, $hostId);
        return is_array($data['vulnerabilities'] ?? null) ? $data['vulnerabilities'] : [];
    }

    private function request(string $method, string $path): array
    {
        $baseUrl = trim((string) ($this->config->fields['api_url'] ?? ''));
        $accessKey = trim((string) ($this->config->fields['access_key'] ?? ''));
        $secretKey = trim((string) ($this->config->fields['secret_key'] ?? ''));
        $timeout = max(1, (int) ($this->config->fields['timeout'] ?? 30));

        if ($baseUrl === '') {
            throw new RuntimeException(__('Nessus API URL is not configured.', 'nessusglpi'));
        }

        if (!$this->isValidBaseUrl($baseUrl)) {
            throw new RuntimeException(__('Invalid Nessus API URL. Use something like https://nessus.example.local:8834', 'nessusglpi'));
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

            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST  => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => min($timeout, 10),
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
            ]);

            $body = curl_exec($ch);
            if ($body === false) {
                $error = curl_error($ch);
                curl_close($ch);
                throw new RuntimeException($this->humanizeCurlError($error));
            }

            $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } catch (Throwable $e) {
            throw new RuntimeException($this->humanizeRuntimeError($e->getMessage()), 0, $e);
        } finally {
            restore_error_handler();
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            if ($statusCode === 0) {
                throw new RuntimeException(__('No valid response was received from the Nessus server.', 'nessusglpi'));
            }

            throw new RuntimeException(__('Nessus API returned an invalid JSON response.', 'nessusglpi'));
        }

        if ($statusCode >= 400) {
            $message = (string) ($decoded['error'] ?? $decoded['message'] ?? ('HTTP ' . $statusCode));
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

        return in_array($scheme, ['http', 'https'], true) && $host !== '';
    }

    private function humanizeCurlError(string $error): string
    {
        $normalized = trim($error);
        $lower = strtolower($normalized);

        if ($normalized === '') {
            return __('Unknown connection error while contacting Nessus.', 'nessusglpi');
        }

        if (str_contains($lower, 'could not resolve host')) {
            return __('Unable to resolve the Nessus host name. Check the URL.', 'nessusglpi');
        }

        if (str_contains($lower, 'failed to connect')) {
            return __('Unable to connect to the Nessus server. Check the URL, port and firewall.', 'nessusglpi');
        }

        if (str_contains($lower, 'timed out')) {
            return __('Connection to the Nessus server timed out.', 'nessusglpi');
        }

        if (str_contains($lower, 'ssl')) {
            return __('SSL error while connecting to Nessus.', 'nessusglpi');
        }

        return $normalized;
    }

    private function humanizeRuntimeError(string $message): string
    {
        $normalized = trim($message);
        $lower = strtolower($normalized);

        if (str_contains($lower, 'contains control characters')) {
            return __('Invalid Nessus API URL. Check for spaces or invalid characters.', 'nessusglpi');
        }

        if (str_contains($lower, 'must be a string') || str_contains($lower, 'must not contain')) {
            return __('Invalid Nessus API URL.', 'nessusglpi');
        }

        return $normalized === ''
            ? __('Unexpected error while testing the Nessus connection.', 'nessusglpi')
            : $normalized;
    }
}
