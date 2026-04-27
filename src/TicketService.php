<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use RuntimeException;
use Throwable;

class TicketService
{
    public function createTicketFromVulnerability(int $vulnerabilityId, bool $forceNew = false): int
    {
        $vulnerability = new Vulnerability();
        if (!$vulnerability->getFromDB($vulnerabilityId)) {
            throw new RuntimeException(__('Vulnerability not found.', 'nessusglpi'));
        }

        if (!$forceNew) {
            $existingTicketId = $this->findExistingVulnerabilityTicket($vulnerability->fields);
            if ($existingTicketId !== null) {
                $this->ensureCurrentVulnerabilityLink($vulnerabilityId, $existingTicketId);
                return $existingTicketId;
            }
        }

        $host = $this->loadHost((int) ($vulnerability->fields['plugin_nessusglpi_hosts_id'] ?? 0));
        $scan = $this->loadScan((int) ($vulnerability->fields['plugin_nessusglpi_scans_id'] ?? 0));
        $pluginDetails = $this->loadPluginDetails($vulnerability->fields, $host?->fields ?? null, $scan?->fields ?? null);

        $title = $this->buildVulnerabilityTitle($vulnerability->fields, $host?->fields ?? null);
        $content = $this->buildVulnerabilityContent($vulnerability->fields, $host?->fields ?? null, $scan?->fields ?? null, $pluginDetails);

        $ticketInput = [
            'name'    => $title,
            'content' => $content,
            'status'  => 1,
            'type'    => 1,
        ];

        $entityId = $this->resolveTicketEntityId($scan?->fields ?? null, (string) ($vulnerability->fields['itemtype'] ?? ''), (int) ($vulnerability->fields['items_id'] ?? 0));
        if ($entityId !== null) {
            $ticketInput['entities_id'] = $entityId;
        }

        $ticket = new \Ticket();
        $ticketId = $ticket->add($ticketInput);

        if (!$ticketId) {
            throw new RuntimeException(__('Unable to create the ticket.', 'nessusglpi'));
        }

        $this->linkTicketToAsset($ticketId, (string) ($vulnerability->fields['itemtype'] ?? ''), (int) ($vulnerability->fields['items_id'] ?? 0));
        $this->ensureCurrentVulnerabilityLink($vulnerabilityId, $ticketId);

        return (int) $ticketId;
    }

    public function createGroupedTicketsFromVulnerabilities(array $vulnerabilityIds, bool $forceNew = false): array
    {
        $groups = [];

        foreach (array_values(array_unique(array_map('intval', $vulnerabilityIds))) as $vulnerabilityId) {
            if ($vulnerabilityId <= 0) {
                continue;
            }

            $vulnerability = new Vulnerability();
            if (!$vulnerability->getFromDB($vulnerabilityId)) {
                throw new RuntimeException(__('Vulnerability not found.', 'nessusglpi'));
            }

            $groupKey = $this->buildGroupedVulnerabilityKey($vulnerability->fields);
            if (!isset($groups[$groupKey])) {
                $groups[$groupKey] = [];
            }

            $groups[$groupKey][] = $vulnerability->fields;
        }

        $ticketIds = [];
        foreach ($groups as $groupRows) {
            $ticketId = $this->createTicketFromVulnerabilityGroup($groupRows, $forceNew);
            if ($ticketId > 0) {
                $ticketIds[] = $ticketId;
            }
        }

        return array_values(array_unique($ticketIds));
    }

    public function createTicketFromHost(int $hostId): int
    {
        $host = new Host();
        if (!$host->getFromDB($hostId)) {
            throw new RuntimeException(__('Host not found.', 'nessusglpi'));
        }

        $existingTicketId = $this->findExistingHostTicket($hostId);
        if ($existingTicketId !== null) {
            return $existingTicketId;
        }

        $scan = $this->loadScan((int) ($host->fields['plugin_nessusglpi_scans_id'] ?? 0));

        $label = (string) ($host->fields['fqdn'] ?: $host->fields['hostname'] ?: $host->fields['ip'] ?: __('Unknown host', 'nessusglpi'));
        $ticketInput = [
            'name'    => sprintf(__('[Nessus] Pending host: %s', 'nessusglpi'), $label),
            'content' => $this->buildHostContent($host->fields),
            'status'  => 1,
            'type'    => 1,
        ];

        $entityId = $this->resolveTicketEntityId($scan?->fields ?? null, (string) ($host->fields['itemtype'] ?? ''), (int) ($host->fields['items_id'] ?? 0));
        if ($entityId !== null) {
            $ticketInput['entities_id'] = $entityId;
        }

        $ticket = new \Ticket();
        $ticketId = $ticket->add($ticketInput);

        if (!$ticketId) {
            throw new RuntimeException(__('Unable to create the ticket.', 'nessusglpi'));
        }

        $this->linkTicketToAsset($ticketId, (string) ($host->fields['itemtype'] ?? ''), (int) ($host->fields['items_id'] ?? 0));

        $link = new HostTicket();
        $link->add([
            'plugin_nessusglpi_hosts_id' => $hostId,
            'tickets_id'                 => $ticketId,
            'date_creation'              => date('Y-m-d H:i:s'),
        ]);

        return (int) $ticketId;
    }

    private function createTicketFromVulnerabilityGroup(array $groupRows, bool $forceNew = false): int
    {
        if ($groupRows === []) {
            throw new RuntimeException(__('No vulnerabilities were selected.', 'nessusglpi'));
        }

        if (!$forceNew) {
            $existingTicketId = $this->findExistingGroupedVulnerabilityTicket($groupRows);
            if ($existingTicketId !== null) {
                foreach ($groupRows as $row) {
                    $this->ensureCurrentVulnerabilityLink((int) ($row['id'] ?? 0), $existingTicketId);
                    $this->linkTicketToAsset($existingTicketId, (string) ($row['itemtype'] ?? ''), (int) ($row['items_id'] ?? 0));
                }

                return $existingTicketId;
            }
        }

        $representative = $groupRows[0];
        $host = $this->loadHost((int) ($representative['plugin_nessusglpi_hosts_id'] ?? 0));
        $scan = $this->loadScan((int) ($representative['plugin_nessusglpi_scans_id'] ?? 0));
        $pluginDetails = $this->loadPluginDetails($representative, $host?->fields ?? null, $scan?->fields ?? null);

        $ticketInput = [
            'name'    => $this->buildGroupedVulnerabilityTitle($representative, $groupRows),
            'content' => $this->buildGroupedVulnerabilityContent($representative, $groupRows, $pluginDetails),
            'status'  => 1,
            'type'    => 1,
        ];

        $entityId = $this->resolveGroupedTicketEntityId($groupRows, $scan?->fields ?? null);
        if ($entityId !== null) {
            $ticketInput['entities_id'] = $entityId;
        }

        $ticket = new \Ticket();
        $ticketId = $ticket->add($ticketInput);
        if (!$ticketId) {
            throw new RuntimeException(__('Unable to create the ticket.', 'nessusglpi'));
        }

        foreach ($groupRows as $row) {
            $this->linkTicketToAsset($ticketId, (string) ($row['itemtype'] ?? ''), (int) ($row['items_id'] ?? 0));
            $this->ensureCurrentVulnerabilityLink((int) ($row['id'] ?? 0), $ticketId);
        }

        return (int) $ticketId;
    }

    private function loadHost(int $hostId): ?Host
    {
        if ($hostId <= 0) {
            return null;
        }

        $host = new Host();
        return $host->getFromDB($hostId) ? $host : null;
    }

    private function loadScan(int $scanId): ?Scan
    {
        if ($scanId <= 0) {
            return null;
        }

        $scan = new Scan();
        return $scan->getFromDB($scanId) ? $scan : null;
    }

    private function loadPluginDetails(array $vulnerabilityFields, ?array $hostFields, ?array $scanFields): ?array
    {
        $nessusHostId = trim((string) ($hostFields['nessus_host_id'] ?? ''));
        $pluginId = trim((string) ($vulnerabilityFields['plugin_id_nessus'] ?? ''));
        $scanId = trim((string) ($scanFields['scan_id'] ?? ''));

        if ($nessusHostId === '' || $pluginId === '' || $scanId === '') {
            return null;
        }

        try {
            return (new NessusClient())->getScanHostPluginDetails($scanId, $nessusHostId, $pluginId);
        } catch (Throwable $e) {
            return [
                '_load_error' => $e->getMessage(),
            ];
        }
    }

    private function findExistingVulnerabilityTicket(array $vulnerabilityFields): ?int
    {
        global $DB;

        $equivalentIds = Vulnerability::getEquivalentVulnerabilityIds($vulnerabilityFields);
        if ($equivalentIds === []) {
            return null;
        }

        $iterator = $DB->request([
            'FROM'  => VulnerabilityTicket::getTable(),
            'WHERE' => [
                'plugin_nessusglpi_vulnerabilities_id' => $equivalentIds,
            ],
            'ORDER' => ['id DESC'],
        ]);

        foreach ($iterator as $row) {
            $ticketId = (int) ($row['tickets_id'] ?? 0);
            if ($ticketId <= 0) {
                continue;
            }

            if ($this->isTicketUsable($ticketId)) {
                return $ticketId;
            }
        }

        return null;
    }

    private function findExistingGroupedVulnerabilityTicket(array $groupRows): ?int
    {
        foreach ($groupRows as $row) {
            $ticketId = $this->findTicketLinkedDirectlyToVulnerability((int) ($row['id'] ?? 0));
            if ($ticketId !== null) {
                return $ticketId;
            }
        }

        return null;
    }

    private function findTicketLinkedDirectlyToVulnerability(int $vulnerabilityId): ?int
    {
        global $DB;

        if ($vulnerabilityId <= 0) {
            return null;
        }

        $iterator = $DB->request([
            'FROM'  => VulnerabilityTicket::getTable(),
            'WHERE' => [
                'plugin_nessusglpi_vulnerabilities_id' => $vulnerabilityId,
            ],
            'ORDER' => ['id DESC'],
        ]);

        foreach ($iterator as $row) {
            $ticketId = (int) ($row['tickets_id'] ?? 0);
            if ($ticketId > 0 && $this->isTicketUsable($ticketId)) {
                return $ticketId;
            }
        }

        return null;
    }

    private function ensureCurrentVulnerabilityLink(int $vulnerabilityId, int $ticketId): void
    {
        global $DB;

        if ($vulnerabilityId <= 0 || $ticketId <= 0) {
            return;
        }

        $existing = $DB->request([
            'FROM'  => VulnerabilityTicket::getTable(),
            'WHERE' => [
                'plugin_nessusglpi_vulnerabilities_id' => $vulnerabilityId,
                'tickets_id'                           => $ticketId,
            ],
            'LIMIT' => 1,
        ])->current();

        if ($existing) {
            return;
        }

        $link = new VulnerabilityTicket();
        $link->add([
            'plugin_nessusglpi_vulnerabilities_id' => $vulnerabilityId,
            'tickets_id'                           => $ticketId,
            'date_creation'                        => date('Y-m-d H:i:s'),
        ]);
    }

    private function findExistingHostTicket(int $hostId): ?int
    {
        global $DB;

        $iterator = $DB->request([
            'FROM'  => HostTicket::getTable(),
            'WHERE' => [
                'plugin_nessusglpi_hosts_id' => $hostId,
            ],
            'ORDER' => ['id DESC'],
        ]);

        foreach ($iterator as $row) {
            $ticketId = (int) ($row['tickets_id'] ?? 0);
            if ($ticketId <= 0) {
                continue;
            }

            if ($this->isTicketUsable($ticketId)) {
                return $ticketId;
            }
        }

        return null;
    }

    private function resolveTicketEntityId(?array $scanFields, string $itemtype, int $itemsId): ?int
    {
        $scanEntityId = $scanFields['entities_id'] ?? null;
        if ($scanEntityId !== null && $scanEntityId !== '') {
            return (int) $scanEntityId;
        }

        $entityId = $this->getLinkedItemEntityId($itemtype, $itemsId);
        if ($entityId !== null) {
            return $entityId;
        }

        if (class_exists(\Session::class) && method_exists(\Session::class, 'getActiveEntity')) {
            $activeEntityId = \Session::getActiveEntity();
            if ($activeEntityId !== null && $activeEntityId !== '') {
                return (int) $activeEntityId;
            }
        }

        return null;
    }

    private function resolveGroupedTicketEntityId(array $groupRows, ?array $scanFields): ?int
    {
        foreach ($groupRows as $row) {
            $entityId = $this->resolveTicketEntityId($scanFields, (string) ($row['itemtype'] ?? ''), (int) ($row['items_id'] ?? 0));
            if ($entityId !== null) {
                return $entityId;
            }
        }

        return $this->resolveTicketEntityId($scanFields, '', 0);
    }

    private function getLinkedItemEntityId(string $itemtype, int $itemsId): ?int
    {
        if ($itemtype === '' || $itemsId <= 0 || !class_exists($itemtype)) {
            return null;
        }

        $item = new $itemtype();
        if (!method_exists($item, 'getFromDB') || !$item->getFromDB($itemsId)) {
            return null;
        }

        $entityId = $item->fields['entities_id'] ?? null;
        if ($entityId === null || $entityId === '') {
            return null;
        }

        return (int) $entityId;
    }

    private function isTicketUsable(int $ticketId): bool
    {
        if ($ticketId <= 0) {
            return false;
        }

        $ticket = new \Ticket();
        if (!$ticket->getFromDB($ticketId)) {
            return false;
        }

        return (int) ($ticket->fields['is_deleted'] ?? 0) === 0;
    }

    private function linkTicketToAsset(int $ticketId, string $itemtype, int $itemsId): void
    {
        global $DB;

        if ($ticketId <= 0 || $itemtype === '' || $itemsId <= 0) {
            return;
        }

        $existing = $DB->request([
            'FROM'  => \Item_Ticket::getTable(),
            'WHERE' => [
                'tickets_id' => $ticketId,
                'itemtype'   => $itemtype,
                'items_id'   => $itemsId,
            ],
            'LIMIT' => 1,
        ])->current();

        if ($existing) {
            return;
        }

        $itemTicket = new \Item_Ticket();
        $itemTicket->add([
            'tickets_id' => $ticketId,
            'itemtype'   => $itemtype,
            'items_id'   => $itemsId,
        ]);
    }

    private function buildVulnerabilityTitle(array $fields, ?array $hostFields): string
    {
        $severity = $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), (int) ($fields['severity'] ?? 0));
        $hostLabel = $this->buildHostLabel($hostFields);
        $name = trim((string) ($fields['plugin_name'] ?? ''));
        if ($name === '') {
            $name = __('Nessus vulnerability', 'nessusglpi');
        }

        return sprintf('[%s] %s - %s', $severity, $hostLabel, $name);
    }

    private function buildGroupedVulnerabilityTitle(array $fields, array $groupRows): string
    {
        $severity = $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), (int) ($fields['severity'] ?? 0));
        $name = trim((string) ($fields['plugin_name'] ?? ''));
        if ($name === '') {
            $name = __('Nessus vulnerability', 'nessusglpi');
        }

        $targets = $this->collectAffectedTargets($groupRows);
        if (count($targets) <= 1) {
            $singleLabel = $targets[0]['label'] ?? __('Unknown host', 'nessusglpi');
            return sprintf('[%s] %s - %s', $severity, $singleLabel, $name);
        }

        return sprintf('[%s] %s - %s', $severity, sprintf(__('Multiple assets (%d)', 'nessusglpi'), count($targets)), $name);
    }

    private function buildVulnerabilityContent(array $fields, ?array $hostFields, ?array $scanFields, ?array $pluginDetails): string
    {
        $hostLabel = $this->buildHostLabel($hostFields);
        $overview = [
            __('Vulnerability imported from Nessus.', 'nessusglpi'),
            '',
            __('Name', 'nessusglpi') . ': ' . (string) ($fields['plugin_name'] ?? ''),
            __('Severity', 'nessusglpi') . ': ' . $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), (int) ($fields['severity'] ?? 0)),
            'Plugin ID: ' . (string) ($fields['plugin_id_nessus'] ?? ''),
            'Scan ID: ' . (string) ($scanFields['scan_id'] ?? ''),
            'Host: ' . $hostLabel,
            __('Last seen', 'nessusglpi') . ': ' . (string) ($fields['last_seen_at'] ?? ''),
            '',
        ];

        $sections = [
            __('Overview', 'nessusglpi') => [
                'CVE' => $pluginDetails['cve'] ?? $fields['cve'] ?? '',
                __('Port', 'nessusglpi') => $pluginDetails['port'] ?? $fields['port'] ?? '',
                __('Protocol', 'nessusglpi') => $pluginDetails['protocol'] ?? $fields['protocol'] ?? '',
                __('Synopsis', 'nessusglpi') => $pluginDetails['synopsis'] ?? $fields['synopsis'] ?? '',
                __('Description') => $pluginDetails['description'] ?? $fields['description'] ?? '',
                __('Solution') => $pluginDetails['solution'] ?? $fields['solution'] ?? '',
                __('Plugin output', 'nessusglpi') => $pluginDetails['plugin_output'] ?? $fields['plugin_output'] ?? '',
            ],
        ];

        if (is_array($pluginDetails)) {
            if (!empty($pluginDetails['_load_error'])) {
                $sections[__('Nessus detail error', 'nessusglpi')] = [
                    __('Message') => (string) $pluginDetails['_load_error'],
                ];
            }

            foreach ([
                __('Plugin attributes', 'nessusglpi') => $pluginDetails['plugin_attributes'] ?? null,
                __('Plugin information', 'nessusglpi') => $pluginDetails['plugin_information'] ?? null,
                __('Risk information', 'nessusglpi') => $pluginDetails['risk_information'] ?? null,
                'VPR' => $pluginDetails['vpr'] ?? null,
                __('Outputs', 'nessusglpi') => $pluginDetails['outputs'] ?? null,
            ] as $title => $data) {
                if ($data !== null) {
                    $sections[(string) $title] = $data;
                }
            }
        }

        $lines = $overview;
        foreach ($sections as $title => $data) {
            $lines[] = '=== ' . $title . ' ===';
            foreach ($this->flattenSection($data) as $line) {
                $lines[] = $line;
            }
            $lines[] = '';
        }

        return trim(implode("\n", $lines));
    }

    private function buildGroupedVulnerabilityContent(array $fields, array $groupRows, ?array $pluginDetails): string
    {
        $targets = $this->collectAffectedTargets($groupRows);
        $scanIds = [];
        foreach ($groupRows as $row) {
            $scanId = (int) ($row['plugin_nessusglpi_scans_id'] ?? 0);
            if ($scanId > 0) {
                $scan = $this->loadScan($scanId);
                if ($scan !== null) {
                    $externalScanId = trim((string) ($scan->fields['scan_id'] ?? ''));
                    if ($externalScanId !== '') {
                        $scanIds[] = $externalScanId;
                    }
                }
            }
        }

        $lines = [
            __('Vulnerability imported from Nessus affecting multiple assets.', 'nessusglpi'),
            '',
            __('Name', 'nessusglpi') . ': ' . (string) ($fields['plugin_name'] ?? ''),
            __('Severity', 'nessusglpi') . ': ' . $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), (int) ($fields['severity'] ?? 0)),
            'Plugin ID: ' . (string) ($fields['plugin_id_nessus'] ?? ''),
        ];

        if ($scanIds !== []) {
            $lines[] = 'Scan IDs: ' . implode(', ', array_values(array_unique($scanIds)));
        }

        $lines[] = '';
        $lines[] = '=== ' . __('Affected assets', 'nessusglpi') . ' ===';
        foreach ($targets as $target) {
            $lines[] = '- ' . $target['label'];
        }
        $lines[] = '';
        $lines[] = '=== ' . __('Overview', 'nessusglpi') . ' ===';

        foreach ($this->flattenSection([
            'CVE' => $pluginDetails['cve'] ?? $fields['cve'] ?? '',
            __('Port', 'nessusglpi') => $pluginDetails['port'] ?? $fields['port'] ?? '',
            __('Protocol', 'nessusglpi') => $pluginDetails['protocol'] ?? $fields['protocol'] ?? '',
            __('Synopsis', 'nessusglpi') => $pluginDetails['synopsis'] ?? $fields['synopsis'] ?? '',
            __('Description') => $pluginDetails['description'] ?? $fields['description'] ?? '',
            __('Solution') => $pluginDetails['solution'] ?? $fields['solution'] ?? '',
            __('Plugin output', 'nessusglpi') => $pluginDetails['plugin_output'] ?? $fields['plugin_output'] ?? '',
        ]) as $line) {
            $lines[] = $line;
        }

        if (is_array($pluginDetails)) {
            foreach ([
                __('Plugin attributes', 'nessusglpi') => $pluginDetails['plugin_attributes'] ?? null,
                __('Plugin information', 'nessusglpi') => $pluginDetails['plugin_information'] ?? null,
                __('Risk information', 'nessusglpi') => $pluginDetails['risk_information'] ?? null,
                'VPR' => $pluginDetails['vpr'] ?? null,
                __('Outputs', 'nessusglpi') => $pluginDetails['outputs'] ?? null,
            ] as $title => $data) {
                if ($data === null) {
                    continue;
                }

                $lines[] = '';
                $lines[] = '=== ' . $title . ' ===';
                foreach ($this->flattenSection($data) as $line) {
                    $lines[] = $line;
                }
            }

            if (!empty($pluginDetails['_load_error'])) {
                $lines[] = '';
                $lines[] = '=== ' . __('Nessus detail error', 'nessusglpi') . ' ===';
                $lines[] = __('Message') . ': ' . (string) $pluginDetails['_load_error'];
            }
        }

        return trim(implode("\n", $lines));
    }

    private function buildHostContent(array $fields): string
    {
        $lines = [
            __('Host imported from Nessus without a confirmed asset link.', 'nessusglpi'),
            '',
            'Hostname: ' . (string) ($fields['hostname'] ?? ''),
            'FQDN: ' . (string) ($fields['fqdn'] ?? ''),
            'IP: ' . (string) ($fields['ip'] ?? ''),
            __('Match status', 'nessusglpi') . ': ' . (string) ($fields['match_status'] ?? ''),
            __('Details') . ': ' . (string) ($fields['match_message'] ?? ''),
        ];

        return trim(implode("\n", $lines));
    }

    private function buildHostLabel(?array $hostFields): string
    {
        if (!is_array($hostFields)) {
            return __('Unknown host', 'nessusglpi');
        }

        $fqdn = trim((string) ($hostFields['fqdn'] ?? ''));
        if ($fqdn !== '') {
            return $fqdn;
        }

        $hostname = trim((string) ($hostFields['hostname'] ?? ''));
        if ($hostname !== '') {
            return $hostname;
        }

        $ip = trim((string) ($hostFields['ip'] ?? ''));
        if ($ip !== '') {
            return $ip;
        }

        return __('Unknown host', 'nessusglpi');
    }

    private function collectAffectedTargets(array $groupRows): array
    {
        $targets = [];

        foreach ($groupRows as $row) {
            $key = $this->buildAffectedTargetKey($row);
            if (isset($targets[$key])) {
                continue;
            }

            $targets[$key] = [
                'label' => $this->buildAffectedTargetLabel($row),
            ];
        }

        return array_values($targets);
    }

    private function buildAffectedTargetKey(array $row): string
    {
        $itemtype = trim((string) ($row['itemtype'] ?? ''));
        $itemsId = (int) ($row['items_id'] ?? 0);
        if ($itemtype !== '' && $itemsId > 0) {
            return $itemtype . ':' . $itemsId;
        }

        $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
        if ($host !== null) {
            $fqdn = trim((string) ($host->fields['fqdn'] ?? ''));
            $hostname = trim((string) ($host->fields['hostname'] ?? ''));
            $ip = trim((string) ($host->fields['ip'] ?? ''));
            return 'host:' . ($fqdn !== '' ? $fqdn : ($hostname !== '' ? $hostname : $ip));
        }

        return 'vulnerability:' . (int) ($row['id'] ?? 0);
    }

    private function buildAffectedTargetLabel(array $row): string
    {
        $itemtype = trim((string) ($row['itemtype'] ?? ''));
        $itemsId = (int) ($row['items_id'] ?? 0);
        if ($itemtype !== '' && $itemsId > 0 && class_exists($itemtype)) {
            $item = new $itemtype();
            if (method_exists($item, 'getFromDB') && $item->getFromDB($itemsId)) {
                if (method_exists($item, 'getName')) {
                    $name = trim((string) $item->getName());
                    if ($name !== '') {
                        return $name;
                    }
                }

                $name = trim((string) ($item->fields['name'] ?? ''));
                if ($name !== '') {
                    return $name;
                }
            }
        }

        $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
        if ($host !== null) {
            return $this->buildHostLabel($host->fields);
        }

        return __('Unknown host', 'nessusglpi');
    }

    private function buildGroupedVulnerabilityKey(array $fields): string
    {
        $parts = [
            (string) ($fields['plugin_id_nessus'] ?? ''),
            strtolower(trim((string) ($fields['plugin_name'] ?? ''))),
            strtolower(trim((string) ($fields['port'] ?? ''))),
            strtolower(trim((string) ($fields['protocol'] ?? ''))),
            (string) ((int) ($fields['severity'] ?? 0)),
            trim((string) ($fields['severity_label'] ?? '')),
        ];

        return sha1(implode('|', $parts));
    }

    private function normalizeSeverityLabel(string $label, int $severity): string
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

    private function flattenSection($data): array
    {
        if (!is_array($data)) {
            $text = trim((string) $data);
            return $text !== '' ? [$text] : [];
        }

        $lines = [];
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $encoded = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $text = trim((string) $encoded);
            } else {
                $text = trim((string) $value);
            }

            if ($text === '') {
                continue;
            }

            $lines[] = (string) $key . ': ' . $text;
        }

        return $lines;
    }
}
