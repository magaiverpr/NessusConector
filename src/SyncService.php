<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use RuntimeException;
use Throwable;

class SyncService
{
    public function runScan(int $scanId): int
    {
        global $DB;

        $scan = new Scan();
        if (!$scan->getFromDB($scanId)) {
            throw new RuntimeException(__('Scan not found.', 'nessusglpi'));
        }

        $scanRun = new ScanRun();
        $now = date('Y-m-d H:i:s');
        $runId = $scanRun->add([
            'plugin_nessusglpi_scans_id' => $scanId,
            'started_at'                 => $now,
            'status'                     => 'running',
            'date_creation'              => $now,
        ]);

        if (!$runId) {
            throw new RuntimeException(__('Unable to create scan run.', 'nessusglpi'));
        }

        $scan->update([
            'id'               => $scanId,
            'last_sync_at'     => $now,
            'last_sync_status' => 'running',
        ]);

        try {
            if (Scan::normalizeSource($scan->fields['scan_type'] ?? Scan::SOURCE_NESSUS) === Scan::SOURCE_WAS) {
                return $this->runWasScan($scan, $scanId, (int) $runId, $scanRun);
            }

            $nessusClient = new NessusClient();
            $scanDetails = $nessusClient->getScanDetails((string) $scan->fields['scan_id']);
            $hosts = is_array($scanDetails['hosts'] ?? null) ? $scanDetails['hosts'] : [];
            $scanExecutedAt = $this->extractScanExecutedAt($scanDetails);
            if ($scanExecutedAt !== null) {
                $scan->update([
                    'id'           => $scanId,
                    'last_scan_at' => $scanExecutedAt,
                ]);
            }

            $matcher = new AssetMatcher();
            $allowedItemtypes = Config::getAllowedItemtypes();
            $allowedSeverities = $this->loadAllowedSeveritiesForScan($scanId, $scan->fields['import_severities'] ?? null);
            $importedHosts = 0;
            $importedVulnerabilities = 0;
            $staleMarkedTargets = [];
            $seenHosts = [];
            $seenVulnerabilities = [];

            foreach ($hosts as $hostData) {
                if (!is_array($hostData)) {
                    continue;
                }

                $hostId = $this->extractHostId($hostData);
                $detailedHostData = $hostId !== null
                    ? $nessusClient->getScanHostDetails((string) $scan->fields['scan_id'], (string) $hostId)
                    : [];

                $normalizedHost = $this->normalizeHost($hostData, $detailedHostData);
                if ($normalizedHost['hostname'] === '' && $normalizedHost['ip'] === '') {
                    continue;
                }

                $seenHostKey = $this->buildSeenHostKey($hostId, $normalizedHost);
                if ($seenHostKey !== '' && isset($seenHosts[$seenHostKey])) {
                    continue;
                }
                if ($seenHostKey !== '') {
                    $seenHosts[$seenHostKey] = true;
                }

                $match = $matcher->findMatch($normalizedHost, $allowedItemtypes);
                $hostDbId = $this->saveOrUpdateImportedHost(
                    $scanId,
                    $runId,
                    $hostId !== null ? (string) $hostId : null,
                    $normalizedHost,
                    $match
                );
                if ($hostDbId <= 0) {
                    continue;
                }

                $importedHosts++;

                $this->markCurrentVulnerabilitiesAsStale($match, $normalizedHost, $staleMarkedTargets);

                $vulnerabilities = $this->extractVulnerabilities($detailedHostData);
                foreach ($vulnerabilities as $vulnerabilityData) {
                    $normalizedVulnerability = $this->normalizeVulnerability(
                        $vulnerabilityData,
                        $scanId,
                        $runId,
                        (int) $hostDbId,
                        $normalizedHost,
                        $match
                    );

                    if (!$this->isSeverityAllowed((int) $normalizedVulnerability['severity'], $allowedSeverities)) {
                        continue;
                    }

                    $seenVulnerabilityKey = (int) $hostDbId . ':' . (string) $normalizedVulnerability['vuln_key'];
                    if (isset($seenVulnerabilities[$seenVulnerabilityKey])) {
                        continue;
                    }
                    $seenVulnerabilities[$seenVulnerabilityKey] = true;

                    $vulnerability = new Vulnerability();
                    if ($vulnerability->add($normalizedVulnerability)) {
                        $importedVulnerabilities++;
                    }
                }
            }

            $this->markDisallowedCurrentVulnerabilitiesAsStale($scanId, $allowedSeverities);
            $currentVulnerabilityCount = $this->countCurrentVulnerabilitiesForScan($scanId);

            $finishedAt = date('Y-m-d H:i:s');
            $scanRun->update([
                'id'                    => $runId,
                'finished_at'           => $finishedAt,
                'status'                => 'success',
                'hosts_found'           => $importedHosts,
                'vulnerabilities_found' => $currentVulnerabilityCount,
                'message'               => sprintf(__('Imported %d host(s) and %d vulnerability entries.', 'nessusglpi'), $importedHosts, $currentVulnerabilityCount),
            ]);

            $scan->update([
                'id'               => $scanId,
                'last_sync_at'     => $finishedAt,
                'last_sync_status' => 'success',
            ]);

            $this->autoFollowupDetectedTickets($scanId);
            $this->autoResolveClearedTickets($scanId);

            return (int) $runId;
        } catch (Throwable $e) {
            $finishedAt = date('Y-m-d H:i:s');
            $scanRun->update([
                'id'          => $runId,
                'finished_at' => $finishedAt,
                'status'      => 'error',
                'message'     => $e->getMessage(),
            ]);

            $scan->update([
                'id'               => $scanId,
                'last_sync_at'     => $finishedAt,
                'last_sync_status' => 'error',
            ]);

            throw new RuntimeException($e->getMessage(), 0, $e);
        }
    }

    private function runWasScan(Scan $scan, int $scanId, int $runId, ScanRun $scanRun): int
    {
        $wasClient = new TenableWasClient();
        $externalScanId = trim((string) ($scan->fields['scan_id'] ?? ''));
        $scanDetails = $wasClient->getScanDetails($externalScanId);
        $scanExecutedAt = $this->extractWasScanExecutedAt($scanDetails);

        if ($scanExecutedAt !== null) {
            $scan->update([
                'id'           => $scanId,
                'last_scan_at' => $scanExecutedAt,
            ]);
        }

        $findings = $wasClient->getAllScanVulnerabilities($externalScanId);
        $matcher = new AssetMatcher();
        $allowedItemtypes = Config::getAllowedItemtypes();
        $allowedSeverities = $this->loadAllowedSeveritiesForScan($scanId, $scan->fields['import_severities'] ?? null);
        $importedHosts = 0;
        $staleMarkedTargets = [];
        $seenHosts = [];
        $seenVulnerabilities = [];

        foreach ($findings as $findingData) {
            if (!is_array($findingData)) {
                continue;
            }

            $normalizedHost = $this->normalizeWasHost($findingData, $scanDetails);
            if ($this->buildHostIdentity($normalizedHost) === '') {
                continue;
            }

            $match = $matcher->findMatch($normalizedHost, $allowedItemtypes);
            $hostDbId = $this->saveOrUpdateImportedHost(
                $scanId,
                $runId,
                $this->buildWasHostId($normalizedHost),
                $normalizedHost,
                $match
            );

            if ($hostDbId <= 0) {
                continue;
            }

            $seenHostKey = $this->buildHostIdentity($normalizedHost);
            if ($seenHostKey !== '' && !isset($seenHosts[$seenHostKey])) {
                $seenHosts[$seenHostKey] = true;
                $importedHosts++;
            }

            $this->markCurrentVulnerabilitiesAsStale($match, $normalizedHost, $staleMarkedTargets);

            $normalizedVulnerability = $this->normalizeWasVulnerability(
                $findingData,
                $scanId,
                $runId,
                (int) $hostDbId,
                $normalizedHost,
                $match
            );

            if (!$this->isSeverityAllowed((int) $normalizedVulnerability['severity'], $allowedSeverities)) {
                continue;
            }

            $seenVulnerabilityKey = (int) $hostDbId . ':' . (string) $normalizedVulnerability['vuln_key'];
            if (isset($seenVulnerabilities[$seenVulnerabilityKey])) {
                continue;
            }
            $seenVulnerabilities[$seenVulnerabilityKey] = true;

            $vulnerability = new Vulnerability();
            $vulnerability->add($normalizedVulnerability);
        }

        $this->markDisallowedCurrentVulnerabilitiesAsStale($scanId, $allowedSeverities);
        $currentVulnerabilityCount = $this->countCurrentVulnerabilitiesForScan($scanId);
        $finishedAt = date('Y-m-d H:i:s');

        $scanRun->update([
            'id'                    => $runId,
            'finished_at'           => $finishedAt,
            'status'                => 'success',
            'hosts_found'           => $importedHosts,
            'vulnerabilities_found' => $currentVulnerabilityCount,
            'message'               => sprintf(__('Imported %d web target(s) and %d vulnerability entries from Tenable WAS.', 'nessusglpi'), $importedHosts, $currentVulnerabilityCount),
        ]);

        $scan->update([
            'id'               => $scanId,
            'last_sync_at'     => $finishedAt,
            'last_sync_status' => 'success',
        ]);

        $this->autoFollowupDetectedTickets($scanId);
        $this->autoResolveClearedTickets($scanId);

        return $runId;
    }

    /**
     * Resolves tickets whose vulnerabilities cleared in this sync. Never lets a resolution
     * error fail the synchronization itself.
     */
    private function autoResolveClearedTickets(int $scanId): void
    {
        try {
            (new TicketService())->autoResolveClearedVulnerabilities($scanId);
        } catch (Throwable $e) {
            // Auto-resolution is best-effort; a failure must not abort a successful sync.
        }
    }

    /**
     * Records changed Nessus evidence as ticket follow-ups without blocking the sync.
     */
    private function autoFollowupDetectedTickets(int $scanId): void
    {
        try {
            (new TicketService())->autoFollowupCurrentVulnerabilities($scanId);
        } catch (Throwable $e) {
            // Auto follow-up is best-effort; a failure must not abort a successful sync.
        }
    }

    private function extractWasScanExecutedAt(array $scanDetails): ?string
    {
        $candidates = [];

        foreach ([
            ['completed_at'],
            ['finished_at'],
            ['last_seen'],
            ['last_scan_time'],
            ['scan_time'],
            ['created_at'],
            ['updated_at'],
            ['config', 'updated_at'],
        ] as $path) {
            $value = $this->nestedValue($scanDetails, $path);
            if ($value !== null) {
                $candidates[] = $value;
            }
        }

        foreach ($candidates as $value) {
            $normalized = $this->normalizeDateValue($value);
            if ($normalized !== null) {
                return $normalized;
            }
        }

        return null;
    }

    private function normalizeWasHost(array $findingData, array $scanDetails): array
    {
        $url = $this->firstNestedString($findingData, [
            ['url'],
            ['uri'],
            ['target'],
            ['application_url'],
            ['web_application_url'],
            ['asset', 'url'],
            ['application', 'url'],
            ['web_application', 'url'],
            ['request', 'url'],
        ]);

        if ($url === '') {
            $url = $this->firstNestedString($scanDetails, [
                ['url'],
                ['target'],
                ['application_url'],
                ['web_application_url'],
                ['asset', 'url'],
                ['application', 'url'],
                ['web_application', 'url'],
            ]);
        }

        $urlHost = $this->extractHostFromUrl($url);
        $fqdn = $this->firstNestedString($findingData, [
            ['fqdn'],
            ['hostname'],
            ['domain'],
            ['host'],
            ['asset', 'fqdn'],
            ['asset', 'hostname'],
            ['asset', 'name'],
            ['application', 'fqdn'],
            ['application', 'hostname'],
            ['web_application', 'fqdn'],
            ['web_application', 'hostname'],
        ]);

        if ($fqdn === '') {
            $fqdn = $this->firstNestedString($scanDetails, [
                ['fqdn'],
                ['hostname'],
                ['domain'],
                ['host'],
                ['asset', 'fqdn'],
                ['asset', 'hostname'],
                ['asset', 'name'],
                ['application', 'fqdn'],
                ['application', 'hostname'],
                ['web_application', 'fqdn'],
                ['web_application', 'hostname'],
            ]);
        }

        if ($fqdn === '') {
            $fqdn = $urlHost;
        }

        $hostname = $this->extractShortHostname($fqdn);
        if ($hostname === '' && $fqdn !== '' && !filter_var($fqdn, FILTER_VALIDATE_IP)) {
            $hostname = $fqdn;
        }

        $ip = $this->firstNestedString($findingData, [
            ['ip'],
            ['ipv4'],
            ['asset', 'ip'],
            ['asset', 'ipv4'],
        ]);

        if ($ip === '') {
            $ip = $this->firstNestedString($scanDetails, [
                ['ip'],
                ['ipv4'],
                ['asset', 'ip'],
                ['asset', 'ipv4'],
            ]);
        }

        if (filter_var($fqdn, FILTER_VALIDATE_IP) && $ip === '') {
            $ip = $fqdn;
            $fqdn = '';
        }

        return [
            'hostname' => $hostname,
            'fqdn'     => $fqdn,
            'ip'       => filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '',
        ];
    }

    private function normalizeWasVulnerability(
        array $vulnerabilityData,
        int $scanId,
        int $runId,
        int $hostDbId,
        array $normalizedHost,
        ?array $match
    ): array {
        $findingId = $this->firstNestedString($vulnerabilityData, [
            ['id'],
            ['uuid'],
            ['finding_id'],
            ['vulnerability_id'],
            ['definition', 'id'],
            ['plugin', 'id'],
        ]);
        $encodedFinding = json_encode($vulnerabilityData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pluginId = $this->truncateString($findingId !== '' ? $findingId : sha1(is_string($encodedFinding) ? $encodedFinding : ''), 64);
        $pluginName = $this->firstNestedString($vulnerabilityData, [
            ['name'],
            ['title'],
            ['plugin_name'],
            ['vulnerability_name'],
            ['definition', 'name'],
            ['plugin', 'name'],
        ]);
        if ($pluginName === '') {
            $pluginName = __('Tenable WAS vulnerability', 'nessusglpi');
        }

        $url = $this->firstNestedString($vulnerabilityData, [
            ['url'],
            ['uri'],
            ['target'],
            ['application_url'],
            ['asset', 'url'],
            ['request', 'url'],
        ]);
        $method = strtoupper($this->firstNestedString($vulnerabilityData, [
            ['method'],
            ['http_method'],
            ['request', 'method'],
        ]));
        $port = $this->firstNestedString($vulnerabilityData, [['port'], ['asset', 'port']]);
        if ($port === '' && $url !== '') {
            $urlPort = parse_url($url, PHP_URL_PORT);
            if (is_int($urlPort)) {
                $port = (string) $urlPort;
            }
        }

        $protocol = strtolower($this->firstNestedString($vulnerabilityData, [['protocol'], ['scheme']]));
        if ($protocol === '' && $url !== '') {
            $scheme = parse_url($url, PHP_URL_SCHEME);
            $protocol = is_string($scheme) ? strtolower($scheme) : '';
        }

        $severity = $this->extractSeverity($vulnerabilityData);
        $severityLabel = $this->mapSeverityLabel($severity, $this->firstNestedString($vulnerabilityData, [
            ['severity_label'],
            ['severity_name'],
            ['severity'],
            ['risk_factor'],
        ]));
        $cve = $this->stringifyValue($vulnerabilityData['cve'] ?? $vulnerabilityData['cves'] ?? null);
        $cwe = $this->stringifyValue($vulnerabilityData['cwe'] ?? $vulnerabilityData['cwes'] ?? null);
        $synopsis = $this->firstNestedString($vulnerabilityData, [['synopsis'], ['summary']]);
        $description = $this->joinTextParts([
            $this->firstNestedString($vulnerabilityData, [['description'], ['details'], ['definition', 'description']]),
            $url !== '' ? 'URL: ' . $url : '',
            $method !== '' ? 'Method: ' . $method : '',
            $cwe !== '' ? 'CWE: ' . $cwe : '',
        ]);
        $solution = $this->firstNestedString($vulnerabilityData, [
            ['solution'],
            ['remediation'],
            ['recommendation'],
            ['definition', 'solution'],
        ]);
        $pluginOutput = $this->joinTextParts([
            $this->firstNestedString($vulnerabilityData, [['plugin_output'], ['proof'], ['evidence'], ['output']]),
            $this->stringifyValue($vulnerabilityData['request'] ?? null),
            $this->stringifyValue($vulnerabilityData['response'] ?? null),
        ]);
        $riskFactor = $this->firstNestedString($vulnerabilityData, [['risk_factor'], ['severity']]);
        $cvss = $this->extractDecimal(
            $vulnerabilityData['cvss_base_score']
            ?? $vulnerabilityData['cvss_score']
            ?? $vulnerabilityData['cvss3_base_score']
            ?? null
        );
        $assetKey = $match !== null
            ? ((string) $match['itemtype'] . '#' . (int) $match['items_id'])
            : $this->buildHostIdentity($normalizedHost);
        $vulnKey = sha1(implode('|', [
            'was',
            $assetKey,
            $pluginId,
            strtolower($pluginName),
            strtolower($url),
            strtolower($method),
            $port,
            $protocol,
        ]));

        $now = date('Y-m-d H:i:s');
        $remoteFirstSeen = $this->normalizeDateValue($this->firstNestedString($vulnerabilityData, [
            ['first_seen'],
            ['first_seen_at'],
            ['first_found'],
            ['created_at'],
        ]));
        $remoteLastSeen = $this->normalizeDateValue($this->firstNestedString($vulnerabilityData, [
            ['last_seen'],
            ['last_seen_at'],
            ['last_found'],
            ['updated_at'],
        ]));
        $firstSeen = $remoteFirstSeen ?? $this->findFirstSeenAt($match, $normalizedHost, $vulnKey) ?? $now;

        return [
            'plugin_nessusglpi_scan_runs_id' => $runId,
            'plugin_nessusglpi_hosts_id'     => $hostDbId,
            'plugin_nessusglpi_scans_id'     => $scanId,
            'itemtype'                       => $match['itemtype'] ?? null,
            'items_id'                       => $match['items_id'] ?? 0,
            'vuln_key'                       => $vulnKey,
            'plugin_id_nessus'              => $pluginId,
            'plugin_name'                   => $pluginName,
            'severity'                      => $severity,
            'severity_label'                => $severityLabel,
            'cve'                           => $cve,
            'port'                          => $port,
            'protocol'                      => $protocol,
            'synopsis'                      => $synopsis,
            'description'                   => $description,
            'solution'                      => $solution,
            'plugin_output'                 => $pluginOutput,
            'risk_factor'                   => $riskFactor,
            'cvss_base_score'               => $cvss,
            'is_current'                    => 1,
            'first_seen_at'                 => $firstSeen,
            'last_seen_at'                  => $remoteLastSeen ?? $now,
            'status'                        => strtolower($this->firstNestedString($vulnerabilityData, [['state'], ['status']])) ?: 'open',
            'date_creation'                 => $now,
        ];
    }

    private function extractScanExecutedAt(array $scanDetails): ?string
    {
        $candidates = [];
        $info = is_array($scanDetails['info'] ?? null) ? $scanDetails['info'] : [];

        foreach (['scan_end', 'scanner_end', 'last_modification_date', 'timestamp', 'loaded_plugin_set'] as $key) {
            if (array_key_exists($key, $info)) {
                $candidates[] = $info[$key];
            }
            if (array_key_exists($key, $scanDetails)) {
                $candidates[] = $scanDetails[$key];
            }
        }

        foreach ($candidates as $value) {
            $normalized = $this->normalizeDateValue($value);
            if ($normalized !== null) {
                return $normalized;
            }
        }

        return null;
    }

    private function normalizeDateValue($value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_numeric($value)) {
            $timestamp = (int) $value;
            if ($timestamp > 9999999999) {
                $timestamp = (int) floor($timestamp / 1000);
            }

            if ($timestamp > 0) {
                return date('Y-m-d H:i:s', $timestamp);
            }
        }

        if (is_scalar($value)) {
            $timestamp = strtotime(trim((string) $value));
            if ($timestamp !== false) {
                return date('Y-m-d H:i:s', $timestamp);
            }
        }

        return null;
    }

    private function normalizeHost(array $hostData, array $detailedHostData = []): array
    {
        $info = is_array($detailedHostData['info'] ?? null) ? $detailedHostData['info'] : [];
        $merged = array_merge($hostData, $info, $detailedHostData);

        $fqdn = $this->firstString($merged, ['host-fqdn', 'fqdn', 'hostname', 'netbios_name', 'name']);
        $hostname = $this->extractShortHostname($fqdn);
        if ($hostname === '') {
            $hostname = $this->firstString($merged, ['hostname', 'netbios_name', 'name', 'host-fqdn']);
        }

        $ip = $this->firstString($merged, ['host-ip', 'ip', 'ipv4', 'hostname']);
        if ($ip !== '' && filter_var($hostname, FILTER_VALIDATE_IP)) {
            $hostname = $fqdn !== '' ? $this->extractShortHostname($fqdn) : '';
        }

        return [
            'hostname' => $hostname,
            'fqdn'     => $fqdn,
            'ip'       => filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '',
        ];
    }

    private function normalizeVulnerability(
        array $vulnerabilityData,
        int $scanId,
        int $runId,
        int $hostDbId,
        array $normalizedHost,
        ?array $match
    ): array {
        $pluginId = $this->firstString($vulnerabilityData, ['plugin_id', 'plugin-id', 'id']);
        $pluginName = $this->firstString($vulnerabilityData, ['plugin_name', 'plugin-name', 'name']);
        $port = $this->firstString($vulnerabilityData, ['port']);
        $protocol = strtolower($this->firstString($vulnerabilityData, ['protocol']));
        $severity = $this->extractSeverity($vulnerabilityData);
        $severityLabel = $this->mapSeverityLabel($severity, $this->firstString($vulnerabilityData, ['severity_label', 'severity_name', 'severity']));
        $cve = $this->stringifyValue($vulnerabilityData['cve'] ?? $vulnerabilityData['cves'] ?? null);
        $synopsis = $this->firstString($vulnerabilityData, ['synopsis']);
        $description = $this->firstString($vulnerabilityData, ['description']);
        $solution = $this->firstString($vulnerabilityData, ['solution']);
        $pluginOutput = $this->firstString($vulnerabilityData, ['plugin_output', 'plugin-output']);
        $riskFactor = $this->firstString($vulnerabilityData, ['risk_factor', 'risk-factor']);
        $cvss = $this->extractDecimal($vulnerabilityData['cvss_base_score'] ?? $vulnerabilityData['cvss3_base_score'] ?? null);
        $assetKey = $match !== null
            ? ((string) $match['itemtype'] . '#' . (int) $match['items_id'])
            : $this->buildHostIdentity($normalizedHost);
        $vulnKey = sha1(implode('|', [
            $assetKey,
            $pluginId,
            $pluginName,
            $port,
            $protocol,
        ]));
        $now = date('Y-m-d H:i:s');
        $firstSeen = $this->findFirstSeenAt($match, $normalizedHost, $vulnKey) ?? $now;

        return [
            'plugin_nessusglpi_scan_runs_id' => $runId,
            'plugin_nessusglpi_hosts_id'     => $hostDbId,
            'plugin_nessusglpi_scans_id'     => $scanId,
            'itemtype'                       => $match['itemtype'] ?? null,
            'items_id'                       => $match['items_id'] ?? 0,
            'vuln_key'                       => $vulnKey,
            'plugin_id_nessus'              => $pluginId,
            'plugin_name'                   => $pluginName,
            'severity'                      => $severity,
            'severity_label'                => $severityLabel,
            'cve'                           => $cve,
            'port'                          => $port,
            'protocol'                      => $protocol,
            'synopsis'                      => $synopsis,
            'description'                   => $description,
            'solution'                      => $solution,
            'plugin_output'                 => $pluginOutput,
            'risk_factor'                   => $riskFactor,
            'cvss_base_score'               => $cvss,
            'is_current'                    => 1,
            'first_seen_at'                 => $firstSeen,
            'last_seen_at'                  => $now,
            'status'                        => 'open',
            'date_creation'                 => $now,
        ];
    }

    private function buildSeenHostKey($sourceHostId, array $normalizedHost): string
    {
        $sourceHostId = trim((string) $sourceHostId);
        if ($sourceHostId !== '') {
            return 'source:' . $sourceHostId;
        }

        return $this->buildHostIdentity($normalizedHost);
    }

    private function extractVulnerabilities(array $detailedHostData): array
    {
        $vulnerabilities = $detailedHostData['vulnerabilities'] ?? null;
        return is_array($vulnerabilities) ? array_values(array_filter($vulnerabilities, 'is_array')) : [];
    }

    private function extractHostId(array $hostData): ?int
    {
        foreach (['host_id', 'id'] as $key) {
            if (!array_key_exists($key, $hostData)) {
                continue;
            }

            $value = $hostData[$key];
            if (is_scalar($value) && is_numeric((string) $value)) {
                return (int) $value;
            }
        }

        return null;
    }

    private function extractShortHostname(string $value): string
    {
        $trimmed = trim($value);
        if ($trimmed === '' || filter_var($trimmed, FILTER_VALIDATE_IP)) {
            return '';
        }

        $parts = explode('.', $trimmed);
        return trim((string) ($parts[0] ?? ''));
    }

    private function extractSeverity(array $vulnerabilityData): int
    {
        $rawSeverity = $vulnerabilityData['severity']
            ?? $vulnerabilityData['severity_index']
            ?? $vulnerabilityData['severity_id']
            ?? null;

        if (is_numeric($rawSeverity)) {
            return max(0, min(4, (int) $rawSeverity));
        }

        $normalized = strtolower(trim((string) $rawSeverity));
        return match ($normalized) {
            'critical', 'critica', 'crítica' => 4,
            'high', 'alta' => 3,
            'medium', 'media', 'média' => 2,
            'low', 'baixa' => 1,
            default => 0,
        };
    }

    private function mapSeverityLabel(int $severity, string $label): string
    {
        $trimmed = trim($label);
        if ($trimmed !== '' && !ctype_digit($trimmed)) {
            return $trimmed;
        }

        return match ($severity) {
            4 => 'Critical',
            3 => 'High',
            2 => 'Medium',
            1 => 'Low',
            default => 'Info',
        };
    }

    private function extractDecimal($value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }

        return is_numeric($value) ? (float) $value : null;
    }

    private function stringifyValue($value): string
    {
        if (is_array($value)) {
            foreach ($value as $item) {
                if (is_array($item)) {
                    $encoded = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                    return is_string($encoded) ? $encoded : '';
                }
            }

            $values = array_map(static fn ($item): string => trim((string) $item), $value);
            $values = array_values(array_filter($values, static fn (string $item): bool => $item !== ''));
            return implode(', ', $values);
        }

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        return '';
    }

    private function findFirstSeenAt(?array $match, array $normalizedHost, string $vulnKey): ?string
    {
        global $DB;

        $criteria = [
            'vuln_key' => $vulnKey,
        ];

        if ($match !== null) {
            $criteria['itemtype'] = (string) $match['itemtype'];
            $criteria['items_id'] = (int) $match['items_id'];
        } else {
            $hostIds = $this->findEquivalentHostIds($normalizedHost);
            if ($hostIds === []) {
                return null;
            }

            $criteria['plugin_nessusglpi_hosts_id'] = $hostIds;
        }

        $row = $DB->request([
            'FROM'  => Vulnerability::getTable(),
            'WHERE' => $criteria,
            'ORDER' => ['id DESC'],
            'LIMIT' => 1,
        ])->current();

        return $row['first_seen_at'] ?? null;
    }

    private function markCurrentVulnerabilitiesAsStale(?array $match, array $normalizedHost, array &$staleMarkedTargets): void
    {
        global $DB;

        if ($match !== null) {
            $targetKey = (string) $match['itemtype'] . '#' . (int) $match['items_id'];
            if (isset($staleMarkedTargets[$targetKey])) {
                return;
            }

            $DB->update(Vulnerability::getTable(), [
                'is_current' => 0,
            ], [
                'itemtype'   => (string) $match['itemtype'],
                'items_id'   => (int) $match['items_id'],
                'is_current' => 1,
            ]);

            $hostIds = $this->findEquivalentHostIds($normalizedHost);
            if ($hostIds !== []) {
                $DB->update(Vulnerability::getTable(), [
                    'is_current' => 0,
                ], [
                    'plugin_nessusglpi_hosts_id' => $hostIds,
                    'is_current'                 => 1,
                ]);
            }

            $staleMarkedTargets[$targetKey] = true;
            return;
        }

        $hostIdentity = $this->buildHostIdentity($normalizedHost);
        if ($hostIdentity === '' || isset($staleMarkedTargets[$hostIdentity])) {
            return;
        }

        $hostIds = $this->findEquivalentHostIds($normalizedHost);
        if ($hostIds !== []) {
            $DB->update(Vulnerability::getTable(), [
                'is_current' => 0,
            ], [
                'plugin_nessusglpi_hosts_id' => $hostIds,
                'is_current'                 => 1,
            ]);
        }

        $staleMarkedTargets[$hostIdentity] = true;
    }

    private function saveOrUpdateImportedHost(
        int $scanId,
        int $runId,
        ?string $nessusHostId,
        array $normalizedHost,
        ?array $match
    ): int {
        $host = new Host();
        $existingHostId = $this->findLatestHostForScan($scanId, $normalizedHost);
        $hostInput = [
            'plugin_nessusglpi_scan_runs_id' => $runId,
            'plugin_nessusglpi_scans_id'     => $scanId,
            'nessus_host_id'                 => $nessusHostId,
            'hostname'                       => $normalizedHost['hostname'],
            'fqdn'                           => $normalizedHost['fqdn'],
            'ip'                             => $normalizedHost['ip'],
            'itemtype'                       => $match['itemtype'] ?? null,
            'items_id'                       => $match['items_id'] ?? 0,
            'match_status'                   => $match !== null ? 'matched' : 'pending',
            'match_message'                  => $match !== null
                ? sprintf(__('Matched with %s #%d', 'nessusglpi'), (string) $match['itemtype'], (int) $match['items_id'])
                : __('No asset match found with the configured item types.', 'nessusglpi'),
        ];

        if ($existingHostId > 0 && $host->getFromDB($existingHostId)) {
            $hostInput['id'] = $existingHostId;
            $host->update($hostInput);
            return $existingHostId;
        }

        $hostInput['date_creation'] = date('Y-m-d H:i:s');
        return (int) $host->add($hostInput);
    }

    private function findLatestHostForScan(int $scanId, array $normalizedHost): int
    {
        global $DB;

        $orWhere = $this->buildHostMatchCriteria($normalizedHost);
        if ($orWhere === []) {
            return 0;
        }

        $row = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Host::getTable(),
            'WHERE'  => [
                'plugin_nessusglpi_scans_id' => $scanId,
                'OR'                         => $orWhere,
            ],
            'ORDER'  => ['id DESC'],
            'LIMIT'  => 1,
        ])->current();

        return (int) ($row['id'] ?? 0);
    }

    private function findEquivalentHostIds(array $normalizedHost): array
    {
        global $DB;

        $orWhere = $this->buildHostMatchCriteria($normalizedHost);
        if ($orWhere === []) {
            return [];
        }

        $ids = [];
        $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Host::getTable(),
            'WHERE'  => ['OR' => $orWhere],
        ]);

        foreach ($iterator as $row) {
            $id = (int) ($row['id'] ?? 0);
            if ($id > 0) {
                $ids[] = $id;
            }
        }

        return array_values(array_unique($ids));
    }

    private function buildHostMatchCriteria(array $normalizedHost): array
    {
        $orWhere = [];
        $fqdn = trim((string) ($normalizedHost['fqdn'] ?? ''));
        $hostname = trim((string) ($normalizedHost['hostname'] ?? ''));
        $ip = trim((string) ($normalizedHost['ip'] ?? ''));

        if ($fqdn !== '') {
            $orWhere[] = ['fqdn' => $fqdn];
        }

        if ($hostname !== '') {
            $orWhere[] = ['hostname' => $hostname];
        }

        if ($ip !== '') {
            $orWhere[] = ['ip' => $ip];
        }

        return $orWhere;
    }

    private function buildHostIdentity(array $normalizedHost): string
    {
        $fqdn = trim((string) ($normalizedHost['fqdn'] ?? ''));
        if ($fqdn !== '') {
            return 'fqdn:' . strtolower($fqdn);
        }

        $hostname = trim((string) ($normalizedHost['hostname'] ?? ''));
        if ($hostname !== '') {
            return 'hostname:' . strtolower($hostname);
        }

        $ip = trim((string) ($normalizedHost['ip'] ?? ''));
        if ($ip !== '') {
            return 'ip:' . $ip;
        }

        return '';
    }

    private function buildWasHostId(array $normalizedHost): string
    {
        $identity = $this->buildHostIdentity($normalizedHost);

        return 'was-' . substr(sha1($identity), 0, 40);
    }

    private function firstNestedString(array $data, array $paths): string
    {
        foreach ($paths as $path) {
            $value = $this->nestedValue($data, $path);
            if (is_scalar($value)) {
                $string = trim((string) $value);
                if ($string !== '') {
                    return $string;
                }
            }
        }

        return '';
    }

    private function nestedValue(array $data, array $path)
    {
        $current = $data;

        foreach ($path as $part) {
            if (!is_array($current) || !array_key_exists($part, $current)) {
                return null;
            }

            $current = $current[$part];
        }

        return $current;
    }

    private function extractHostFromUrl(string $url): string
    {
        if ($url === '') {
            return '';
        }

        $host = parse_url($url, PHP_URL_HOST);
        if (is_string($host) && trim($host) !== '') {
            return strtolower(trim($host));
        }

        return '';
    }

    private function truncateString(string $value, int $length): string
    {
        if ($length <= 0) {
            return '';
        }

        return strlen($value) > $length ? substr($value, 0, $length) : $value;
    }

    private function joinTextParts(array $parts): string
    {
        $lines = [];

        foreach ($parts as $part) {
            $text = trim((string) $part);
            if ($text !== '') {
                $lines[] = $text;
            }
        }

        return implode("\n\n", array_values(array_unique($lines)));
    }

    private function firstString(array $data, array $keys): string
    {
        foreach ($keys as $key) {
            if (!array_key_exists($key, $data)) {
                continue;
            }

            $value = $data[$key];
            if (is_scalar($value)) {
                $string = trim((string) $value);
                if ($string !== '') {
                    return $string;
                }
            }
        }

        return '';
    }

    private function loadAllowedSeveritiesForScan(int $scanId, $fallbackRaw): array
    {
        global $DB;

        $row = $DB->request([
            'SELECT' => ['import_severities'],
            'FROM'   => Scan::getTable(),
            'WHERE'  => [
                'id' => $scanId,
            ],
            'LIMIT'  => 1,
        ])->current();

        return Scan::decodeImportSeverities($row['import_severities'] ?? $fallbackRaw);
    }

    private function isSeverityAllowed(int $severity, array $allowedSeverities): bool
    {
        return in_array($severity, $allowedSeverities, true);
    }

    private function markDisallowedCurrentVulnerabilitiesAsStale(int $scanId, array $allowedSeverities): void
    {
        global $DB;

        $allSeverities = array_keys(Scan::getSeverityOptions());
        $disallowedSeverities = array_values(array_diff($allSeverities, $allowedSeverities));
        if ($disallowedSeverities === []) {
            return;
        }

        foreach ($disallowedSeverities as $severity) {
            $DB->update(Vulnerability::getTable(), [
                'is_current' => 0,
            ], [
                'plugin_nessusglpi_scans_id' => $scanId,
                'is_current'                 => 1,
                'severity'                   => (int) $severity,
            ]);
        }
    }

    private function countCurrentVulnerabilitiesForScan(int $scanId): int
    {
        global $DB;

        $count = 0;
        $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Vulnerability::getTable(),
            'WHERE'  => [
                'plugin_nessusglpi_scans_id' => $scanId,
                'is_current'                 => 1,
            ],
        ]);

        foreach ($iterator as $_row) {
            $count++;
        }

        return $count;
    }
}
