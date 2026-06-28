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

        $host = $this->loadHost((int) ($vulnerability->fields['plugin_nessusglpi_hosts_id'] ?? 0));

        if (!$forceNew) {
            $existingTicketId = $this->findExistingVulnerabilityTicket($vulnerability->fields, $host?->fields ?? null);
            if ($existingTicketId !== null) {
                $this->ensureCurrentVulnerabilityLink($vulnerabilityId, $existingTicketId);
                $this->linkTicketToAsset($existingTicketId, (string) ($vulnerability->fields['itemtype'] ?? ''), (int) ($vulnerability->fields['items_id'] ?? 0));
                TicketMemory::rememberVulnerabilityTicket($vulnerability->fields, $host?->fields ?? null, $existingTicketId);
                $this->addCurrentDetectionFollowupIfChanged($existingTicketId, $vulnerability->fields);
                return $existingTicketId;
            }
        }

        $scan = $this->loadScan((int) ($vulnerability->fields['plugin_nessusglpi_scans_id'] ?? 0));
        $pluginDetails = $this->loadPluginDetails($vulnerability->fields, $host?->fields ?? null, $scan?->fields ?? null);
        $detectionSnapshot = $this->buildDetectionSnapshot($vulnerability->fields, $host?->fields ?? null, $scan?->fields ?? null, $pluginDetails);
        $detectionHash = $this->buildDetectionFollowupHash($detectionSnapshot);

        $title = $this->buildVulnerabilityTitle($vulnerability->fields, $host?->fields ?? null);
        $content = $this->appendDetectionHashMarker(
            $this->buildVulnerabilityContent($vulnerability->fields, $host?->fields ?? null, $scan?->fields ?? null, $pluginDetails),
            $detectionHash
        );

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
        TicketMemory::rememberVulnerabilityTicket($vulnerability->fields, $host?->fields ?? null, $ticketId);

        return (int) $ticketId;
    }

    public function autoFollowupCurrentVulnerabilities(int $scanId): int
    {
        global $DB;

        if ($scanId <= 0 || !class_exists(\ITILFollowup::class)) {
            return 0;
        }

        $linkTable = VulnerabilityTicket::getTable();
        $vulnTable = Vulnerability::getTable();

        $iterator = $DB->request([
            'SELECT'     => [
                $linkTable . '.tickets_id',
                $linkTable . '.plugin_nessusglpi_vulnerabilities_id',
            ],
            'FROM'       => $linkTable,
            'INNER JOIN' => [
                $vulnTable => [
                    'FKEY' => [
                        $linkTable => 'plugin_nessusglpi_vulnerabilities_id',
                        $vulnTable => 'id',
                    ],
                ],
            ],
            'WHERE' => [
                $vulnTable . '.plugin_nessusglpi_scans_id' => $scanId,
            ],
            'ORDER' => [$linkTable . '.id DESC'],
        ]);

        $added = 0;
        $processed = [];

        foreach ($iterator as $row) {
            $ticketId = (int) ($row['tickets_id'] ?? 0);
            $linkedVulnerabilityId = (int) ($row['plugin_nessusglpi_vulnerabilities_id'] ?? 0);
            if ($ticketId <= 0 || $linkedVulnerabilityId <= 0 || !$this->isTicketUsable($ticketId)) {
                continue;
            }

            $linkedVulnerability = new Vulnerability();
            if (!$linkedVulnerability->getFromDB($linkedVulnerabilityId)) {
                continue;
            }

            $currentFields = $this->findCurrentEquivalentVulnerabilityFields($linkedVulnerability->fields);
            if ($currentFields === null) {
                continue;
            }

            $currentVulnerabilityId = (int) ($currentFields['id'] ?? 0);
            $processKey = $ticketId . ':' . $currentVulnerabilityId;
            if ($currentVulnerabilityId <= 0 || isset($processed[$processKey])) {
                continue;
            }
            $processed[$processKey] = true;

            $this->ensureCurrentVulnerabilityLink($currentVulnerabilityId, $ticketId);
            if ($this->addCurrentDetectionFollowupIfChanged($ticketId, $currentFields)) {
                $added++;
            }
        }

        if ($added > 0) {
            AuditLog::info('auto-followup', sprintf('Added %d Nessus detection follow-up(s) after scan #%d.', $added, $scanId), [
                'scan_id'  => $scanId,
                'followups' => $added,
            ]);
        }

        return $added;
    }

    /**
     * Create one parent ticket per host + one child ticket per vulnerability on that host.
     *
     * Returns:
     *   [
     *     'groups'   => [
     *         ['parent' => int, 'children' => int[]],
     *         ...
     *     ],
     *     'parents'  => int[],   // flat list of parent ticket IDs (one per host)
     *     'children' => int[],   // flat list of child ticket IDs (one per vulnerability)
     *   ]
     */
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

        $result = [
            'groups'   => [],
            'parents'  => [],
            'children' => [],
        ];

        foreach ($groups as $groupRows) {
            $groupResult = $this->createTicketFromVulnerabilityGroup($groupRows, $forceNew);
            $parentId = (int) ($groupResult['parent'] ?? 0);
            $childIds = array_values(array_unique(array_map('intval', (array) ($groupResult['children'] ?? []))));

            if ($parentId <= 0 && $childIds === []) {
                continue;
            }

            $result['groups'][] = [
                'parent'   => $parentId,
                'children' => $childIds,
            ];

            if ($parentId > 0) {
                $result['parents'][] = $parentId;
            }

            foreach ($childIds as $childId) {
                if ($childId > 0) {
                    $result['children'][] = $childId;
                }
            }
        }

        $result['parents']  = array_values(array_unique($result['parents']));
        $result['children'] = array_values(array_unique($result['children']));

        return $result;
    }

    /**
     * Resolves tickets whose linked vulnerabilities are no longer detected after a sync.
     *
     * A ticket is resolved only when ALL of its linked vulnerabilities have no current
     * (is_current = 1) equivalent left — so a parent ticket covering several findings is
     * only closed once every one of them has cleared.
     *
     * @return int Number of tickets resolved.
     */
    public function autoResolveClearedVulnerabilities(int $scanId): int
    {
        global $DB;

        if ($scanId <= 0) {
            return 0;
        }

        $linkTable = VulnerabilityTicket::getTable();
        $vulnTable = Vulnerability::getTable();

        $iterator = $DB->request([
            'SELECT'     => [$linkTable . '.tickets_id'],
            'DISTINCT'   => true,
            'FROM'       => $linkTable,
            'INNER JOIN' => [
                $vulnTable => [
                    'FKEY' => [
                        $linkTable => 'plugin_nessusglpi_vulnerabilities_id',
                        $vulnTable => 'id',
                    ],
                ],
            ],
            'WHERE' => [
                $vulnTable . '.plugin_nessusglpi_scans_id' => $scanId,
            ],
        ]);

        $resolved = 0;
        foreach ($iterator as $row) {
            $ticketId = (int) ($row['tickets_id'] ?? 0);
            if ($ticketId <= 0) {
                continue;
            }

            if ($this->ticketHasActiveLinkedVulnerability($ticketId)) {
                continue;
            }

            if ($this->resolveTicketAsCleared($ticketId)) {
                $resolved++;
            }
        }

        if ($resolved > 0) {
            AuditLog::info('auto-resolve', sprintf('Auto-resolved %d ticket(s) after scan #%d cleared their vulnerabilities.', $resolved, $scanId), [
                'scan_id'  => $scanId,
                'resolved' => $resolved,
            ]);
        }

        return $resolved;
    }

    private function ticketHasActiveLinkedVulnerability(int $ticketId): bool
    {
        global $DB;

        $iterator = $DB->request([
            'SELECT' => ['plugin_nessusglpi_vulnerabilities_id'],
            'FROM'   => VulnerabilityTicket::getTable(),
            'WHERE'  => ['tickets_id' => $ticketId],
        ]);

        foreach ($iterator as $link) {
            $vulnId = (int) ($link['plugin_nessusglpi_vulnerabilities_id'] ?? 0);
            if ($vulnId <= 0) {
                continue;
            }

            $vulnerability = new Vulnerability();
            if (!$vulnerability->getFromDB($vulnId)) {
                continue;
            }

            if ($this->vulnerabilityStillCurrent($vulnerability->fields)) {
                return true;
            }
        }

        return false;
    }

    private function vulnerabilityStillCurrent(array $vulnerabilityFields): bool
    {
        global $DB;

        $equivalentIds = Vulnerability::getEquivalentVulnerabilityIds($vulnerabilityFields);
        if ($equivalentIds === []) {
            return false;
        }

        $row = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Vulnerability::getTable(),
            'WHERE'  => [
                'id'         => $equivalentIds,
                'is_current' => 1,
            ],
            'LIMIT' => 1,
        ])->current();

        return $row !== null && !empty($row);
    }

    private function resolveTicketAsCleared(int $ticketId): bool
    {
        $ticket = new \Ticket();
        if (!$ticket->getFromDB($ticketId)) {
            return false;
        }

        if ((int) ($ticket->fields['is_deleted'] ?? 0) !== 0) {
            return false;
        }

        // 5 = solved, 6 = closed. Leave already-resolved tickets untouched.
        $status = (int) ($ticket->fields['status'] ?? 0);
        if (in_array($status, [5, 6], true)) {
            return false;
        }

        $content = $this->buildResolutionContent();

        // Preferred path: a real solution moves the ticket to "solved" (reversible — the
        // requester can still reopen it) through GLPI's own workflow.
        if (class_exists(\ITILSolution::class)) {
            try {
                $solution = new \ITILSolution();
                $added = $solution->add([
                    'itemtype' => \Ticket::class,
                    'items_id' => $ticketId,
                    'content'  => $content,
                ]);
                if ($added) {
                    return true;
                }
            } catch (Throwable $e) {
                // Fall through to the lighter-touch path below.
            }
        }

        // Fallback: leave a follow-up note and mark the ticket solved directly.
        if (class_exists(\ITILFollowup::class)) {
            try {
                (new \ITILFollowup())->add([
                    'itemtype' => \Ticket::class,
                    'items_id' => $ticketId,
                    'content'  => $content,
                ]);
            } catch (Throwable $e) {
                // Non-fatal: the status update below is what matters.
            }
        }

        return (bool) $ticket->update(['id' => $ticketId, 'status' => 5]);
    }

    private function buildResolutionContent(): string
    {
        $when = date('Y-m-d H:i:s');

        return '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">'
            . '<div style="padding:12px 16px; background:#ecfdf5; border-left:4px solid #198754; border-radius:6px; color:#065f46; font-size:14px; line-height:1.55;">'
            . '✅ <strong>' . htmlspecialchars(__('Vulnerability no longer detected', 'nessusglpi'), ENT_QUOTES) . '</strong><br>'
            . htmlspecialchars(
                sprintf(
                    __('The latest Nessus synchronization (%s) no longer reports this vulnerability on the affected asset, so this ticket was resolved automatically.', 'nessusglpi'),
                    $when
                ),
                ENT_QUOTES
            )
            . '</div>'
            . $this->renderTicketFooter()
            . '</div>';
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

    /**
     * Builds the ticket hierarchy for a single grouped batch:
     *  - if the group affects 1 host → returns one standalone ticket as parent (no children)
     *  - if the group affects N >= 2 hosts → creates 1 parent ticket + N child tickets linked via Ticket_Ticket SON_OF
     *
     * Returns ['parent' => int, 'children' => int[]].
     */
    private function createTicketFromVulnerabilityGroup(array $groupRows, bool $forceNew = false): array
    {
        if ($groupRows === []) {
            throw new RuntimeException(__('No vulnerabilities were selected.', 'nessusglpi'));
        }

        // One child per affected host: keep the most severe row per host.
        $rowsByHost = $this->dedupGroupRowsByHost($groupRows);

        // Only one host affected by this vulnerability: a single ticket is enough.
        if (count($rowsByHost) <= 1) {
            $only = reset($rowsByHost) ?: ['id' => $groupRows[0]['id'] ?? 0];
            $ticketId = $this->createTicketFromVulnerability((int) ($only['id'] ?? 0), $forceNew);
            return ['parent' => $ticketId, 'children' => []];
        }

        // Try to reuse an existing parent ticket so the user doesn't end up with duplicate parents
        // each time they reissue the grouped creation.
        if (!$forceNew) {
            $existingParentId = $this->findExistingGroupParentTicket($groupRows);
            if ($existingParentId !== null) {
                $childIds = $this->ensureChildTicketsForGroup($existingParentId, $rowsByHost, $forceNew);

                foreach ($groupRows as $row) {
                    $this->ensureCurrentVulnerabilityLink((int) ($row['id'] ?? 0), $existingParentId);
                }

                return ['parent' => $existingParentId, 'children' => $childIds];
            }
        }

        // 1 parent per vulnerability/CVE (overview across hosts) + 1 child per affected host.
        $parentId = $this->createGroupParentTicket($groupRows, $rowsByHost);

        $childIds = [];
        foreach ($rowsByHost as $row) {
            $childId = $this->createTicketFromVulnerability((int) ($row['id'] ?? 0), $forceNew);
            if ($childId <= 0 || $childId === $parentId) {
                continue;
            }
            $this->linkTicketsAsSon($childId, $parentId);
            $childIds[] = $childId;
        }

        return [
            'parent'   => $parentId,
            'children' => array_values(array_unique($childIds)),
        ];
    }

    private function createGroupParentTicket(array $groupRows, array $rowsByHost): int
    {
        $representative = $groupRows[0];
        $scan = $this->loadScan((int) ($representative['plugin_nessusglpi_scans_id'] ?? 0));
        $pluginDetails = $this->loadPluginDetails($representative, null, $scan?->fields ?? null);

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
        $parentId = (int) $ticket->add($ticketInput);
        if ($parentId <= 0) {
            throw new RuntimeException(__('Unable to create the ticket.', 'nessusglpi'));
        }

        // Parent represents the issue across all affected assets — link them all.
        foreach ($rowsByHost as $row) {
            $this->linkTicketToAsset($parentId, (string) ($row['itemtype'] ?? ''), (int) ($row['items_id'] ?? 0));
        }

        // NB: we deliberately do NOT link the vulnerabilities to the parent here.
        // Each vulnerability is linked to its own child ticket (one per host) by
        // createTicketFromVulnerability(); linking them to the parent first would
        // make the child-creation dedup return the parent and skip every child.
        // Re-run dedup still finds the parent by walking child → parent (SON_OF).

        return $parentId;
    }

    private function createHostGroupParentTicket(array $groupRows): int
    {
        $representative = $groupRows[0];
        $host = $this->loadHost((int) ($representative['plugin_nessusglpi_hosts_id'] ?? 0));
        $scan = $this->loadScan((int) ($representative['plugin_nessusglpi_scans_id'] ?? 0));

        $ticketInput = [
            'name'    => $this->buildHostGroupParentTitle($host?->fields ?? null, $groupRows),
            'content' => $this->buildHostGroupParentContent($host?->fields ?? null, $groupRows),
            'status'  => 1,
            'type'    => 1,
        ];

        $entityId = $this->resolveGroupedTicketEntityId($groupRows, $scan?->fields ?? null);
        if ($entityId !== null) {
            $ticketInput['entities_id'] = $entityId;
        }

        $ticket = new \Ticket();
        $parentId = (int) $ticket->add($ticketInput);
        if ($parentId <= 0) {
            throw new RuntimeException(__('Unable to create the ticket.', 'nessusglpi'));
        }

        // Link parent to the host asset.
        $this->linkTicketToAsset(
            $parentId,
            (string) ($representative['itemtype'] ?? ''),
            (int) ($representative['items_id'] ?? 0)
        );

        // Keep the dedup index aware of every vulnerability in this group.
        foreach ($groupRows as $row) {
            $this->ensureCurrentVulnerabilityLink((int) ($row['id'] ?? 0), $parentId);
        }

        return $parentId;
    }

    private function buildHostGroupParentTitle(?array $hostFields, array $groupRows): string
    {
        $label = $this->buildHostLabel($hostFields);
        $count = count($groupRows);
        return sprintf('[Nessus] %s — %s', $label, sprintf(_n('%d vulnerability', '%d vulnerabilities', $count, 'nessusglpi'), $count));
    }

    private function buildHostGroupParentContent(?array $hostFields, array $groupRows): string
    {
        $label  = $this->buildHostLabel($hostFields);
        $ip     = trim((string) ($hostFields['ip'] ?? ''));
        $fqdn   = trim((string) ($hostFields['fqdn'] ?? ''));
        $count  = count($groupRows);

        $maxSeverity      = 0;
        $maxSeverityLabel = '';
        foreach ($groupRows as $row) {
            $sev = (int) ($row['severity'] ?? 0);
            if ($sev > $maxSeverity) {
                $maxSeverity      = $sev;
                $maxSeverityLabel = (string) ($row['severity_label'] ?? '');
            }
        }
        $meta = $this->severityHtmlMeta($maxSeverity, $this->normalizeSeverityLabel($maxSeverityLabel, $maxSeverity));

        $html   = [];
        $html[] = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">';
        $html[] = $this->renderTicketHero(
            $meta,
            htmlspecialchars($label, ENT_QUOTES),
            '🖥️ ' . sprintf(_n('%d vulnerability selected', '%d vulnerabilities selected', $count, 'nessusglpi'), $count)
        );

        $html[] = '<div style="margin:0 0 22px 0; padding:12px 16px; background:#eff6ff; border-left:4px solid #2563eb; border-radius:6px; color:#1e3a8a; font-size:13px; line-height:1.5;">'
            . '<strong>🌳 ' . htmlspecialchars(__('Parent ticket', 'nessusglpi'), ENT_QUOTES) . '</strong> — '
            . htmlspecialchars(
                sprintf(
                    _n(
                        'One child ticket has been created per vulnerability (%d in total). Check the "Linked tickets" panel for the breakdown.',
                        'One child ticket has been created per vulnerability (%d in total). Check the "Linked tickets" panel for the breakdown.',
                        $count,
                        'nessusglpi'
                    ),
                    $count
                ),
                ENT_QUOTES
            )
            . '</div>';

        $hostRows = array_filter([
            '🌐 ' . __('FQDN', 'nessusglpi')        => $fqdn,
            '📡 ' . __('IP address', 'nessusglpi')   => $ip,
        ], static fn ($v) => $v !== '');
        if ($hostRows !== []) {
            $html[] = $this->renderTicketCallout('🖥️ ' . __('Host information', 'nessusglpi'), $hostRows);
        }

        $vulnRows = '';
        usort($groupRows, static fn ($a, $b) => (int) ($b['severity'] ?? 0) <=> (int) ($a['severity'] ?? 0));
        foreach ($groupRows as $row) {
            $sev      = (int) ($row['severity'] ?? 0);
            $sevLabel = $this->normalizeSeverityLabel((string) ($row['severity_label'] ?? ''), $sev);
            $m        = $this->severityHtmlMeta($sev, $sevLabel);
            $vulnName = $this->cleanText((string) ($row['plugin_name'] ?? '')) ?: __('Nessus vulnerability', 'nessusglpi');
            $port     = $this->joinPortProtocol(trim((string) ($row['port'] ?? '')), trim((string) ($row['protocol'] ?? '')));

            $vulnRows .= '<tr>'
                . '<td style="padding:5px 10px; vertical-align:top;">'
                . '<span style="display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'
                . ' background:' . $m['background'] . '; color:' . $m['color'] . '; border:1px solid ' . $m['border'] . ';">'
                . htmlspecialchars($m['icon'] . ' ' . $m['label'], ENT_QUOTES)
                . '</span></td>'
                . '<td style="padding:5px 10px; vertical-align:top; font-size:13px;">'
                . htmlspecialchars($vulnName, ENT_QUOTES) . '</td>'
                . '<td style="padding:5px 10px; vertical-align:top; font-size:12px; color:#6c757d;">'
                . htmlspecialchars($port, ENT_QUOTES) . '</td>'
                . '</tr>';
        }

        $html[] = $this->renderTicketSection(
            '🛡️ ' . __('Selected vulnerabilities', 'nessusglpi') . ' <span style="color:#6c757d; font-weight:400;">(' . $count . ')</span>',
            '<table style="width:100%; border-collapse:collapse; font-size:13px;">'
            . '<thead><tr>'
            . '<th style="padding:5px 10px; text-align:left; border-bottom:1px solid #dee2e6; font-size:11px; color:#6c757d; white-space:nowrap;">' . htmlspecialchars(__('Severity', 'nessusglpi'), ENT_QUOTES) . '</th>'
            . '<th style="padding:5px 10px; text-align:left; border-bottom:1px solid #dee2e6; font-size:11px; color:#6c757d;">' . htmlspecialchars(__('Vulnerability', 'nessusglpi'), ENT_QUOTES) . '</th>'
            . '<th style="padding:5px 10px; text-align:left; border-bottom:1px solid #dee2e6; font-size:11px; color:#6c757d; white-space:nowrap;">' . htmlspecialchars(__('Port', 'nessusglpi'), ENT_QUOTES) . '</th>'
            . '</tr></thead><tbody>'
            . $vulnRows
            . '</tbody></table>'
        );

        $html[] = $this->renderTicketFooter();
        $html[] = '</div>';

        return implode("\n", $html);
    }

    private function ensureChildTicketsForGroup(int $parentId, array $rowsByHost, bool $forceNew): array
    {
        $childIds = [];

        foreach ($rowsByHost as $row) {
            $childId = $this->createTicketFromVulnerability((int) ($row['id'] ?? 0), $forceNew);
            if ($childId <= 0 || $childId === $parentId) {
                continue;
            }
            $this->linkTicketsAsSon($childId, $parentId);
            $childIds[] = $childId;
        }

        return array_values(array_unique($childIds));
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
        if (Scan::normalizeSource($scanFields['scan_type'] ?? Scan::SOURCE_NESSUS) === Scan::SOURCE_WAS) {
            return null;
        }

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

    private function normalizePluginDetails(?array $pluginDetails): array
    {
        $pluginDetails = is_array($pluginDetails) ? $pluginDetails : [];
        $info = is_array($pluginDetails['info'] ?? null) ? $pluginDetails['info'] : [];
        $pluginDescription = is_array($info['plugindescription'] ?? null) ? $info['plugindescription'] : [];
        $pluginAttributes = is_array($pluginDescription['pluginattributes'] ?? null) ? $pluginDescription['pluginattributes'] : [];

        $riskInformation = is_array($pluginAttributes['risk_information'] ?? null)
            ? $pluginAttributes['risk_information']
            : (is_array($pluginDetails['risk_information'] ?? null) ? $pluginDetails['risk_information'] : []);
        $pluginInformation = is_array($pluginAttributes['plugin_information'] ?? null)
            ? $pluginAttributes['plugin_information']
            : (is_array($pluginDetails['plugin_information'] ?? null) ? $pluginDetails['plugin_information'] : []);
        $vulnInformation = is_array($pluginAttributes['vuln_information'] ?? null)
            ? $pluginAttributes['vuln_information']
            : (is_array($pluginDetails['vuln_information'] ?? null) ? $pluginDetails['vuln_information'] : []);
        $refInformation = is_array($pluginAttributes['ref_information'] ?? null)
            ? $pluginAttributes['ref_information']
            : (is_array($pluginDetails['ref_information'] ?? null) ? $pluginDetails['ref_information'] : []);
        $outputs = is_array($pluginDetails['outputs'] ?? null) ? $pluginDetails['outputs'] : [];
        $firstOutput = isset($outputs[0]) && is_array($outputs[0]) ? $outputs[0] : [];
        $cves = $this->extractReferenceValues($refInformation, 'cve');

        return [
            'plugin_id'                => $this->firstNonEmpty([$pluginDescription['pluginid'] ?? null, $pluginDetails['plugin_id'] ?? null, $pluginDetails['pluginid'] ?? null]),
            'plugin_name'              => $this->firstNonEmpty([$pluginDescription['pluginname'] ?? null, $pluginDetails['plugin_name'] ?? null, $pluginDetails['pluginname'] ?? null]),
            'cve'                      => $this->firstNonEmpty([$pluginDetails['cve'] ?? null, implode(', ', $cves)]),
            'see_also'                 => $this->normalizeStringList($pluginAttributes['see_also'] ?? ($pluginDetails['see_also'] ?? [])),
            'synopsis'                 => $this->firstNonEmpty([$pluginAttributes['synopsis'] ?? null, $pluginDetails['synopsis'] ?? null]),
            'description'              => $this->firstNonEmpty([$pluginAttributes['description'] ?? null, $pluginDetails['description'] ?? null]),
            'solution'                 => $this->firstNonEmpty([$pluginAttributes['solution'] ?? null, $pluginDetails['solution'] ?? null]),
            'plugin_output'            => $this->firstNonEmpty([$firstOutput['plugin_output'] ?? null, $pluginDetails['plugin_output'] ?? null]),
            'port'                     => $this->firstNonEmpty([$pluginDetails['port'] ?? null, $firstOutput['port'] ?? null]),
            'protocol'                 => $this->firstNonEmpty([$pluginDetails['protocol'] ?? null, $firstOutput['protocol'] ?? null]),
            'vpr_score'                => $this->firstNonEmpty([$pluginAttributes['vpr_score'] ?? null, $pluginDetails['vpr_score'] ?? null, $pluginDetails['vpr'] ?? null]),
            'risk_information'         => $riskInformation,
            'plugin_information'       => $pluginInformation,
            'vuln_information'         => $vulnInformation,
            'outputs'                  => $outputs,
            '_load_error'              => (string) ($pluginDetails['_load_error'] ?? ''),
        ];
    }

    private function extractReferenceValues(array $refInformation, string $referenceName): array
    {
        $items = [];
        $references = $refInformation['ref'] ?? [];
        if (is_array($references) && !array_is_list($references)) {
            $references = [$references];
        }

        foreach ((array) $references as $reference) {
            if (!is_array($reference) || strtolower((string) ($reference['name'] ?? '')) !== strtolower($referenceName)) {
                continue;
            }

            $values = $reference['values']['value'] ?? [];
            foreach ($this->normalizeStringList($values) as $value) {
                $items[$value] = true;
            }
        }

        return array_keys($items);
    }

    private function normalizeStringList($value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n]+/', $value) ?: [$value];
        }
        if (!is_array($value)) {
            $value = [$value];
        }

        $items = [];
        foreach ($value as $item) {
            if (is_array($item)) {
                foreach ($this->normalizeStringList($item) as $nested) {
                    $items[$nested] = true;
                }
                continue;
            }

            $text = trim((string) $item);
            if ($text !== '') {
                $items[$text] = true;
            }
        }

        return array_keys($items);
    }

    private function findCurrentEquivalentVulnerabilityFields(array $vulnerabilityFields): ?array
    {
        global $DB;

        $equivalentIds = Vulnerability::getEquivalentVulnerabilityIds($vulnerabilityFields);
        if ($equivalentIds === []) {
            return null;
        }

        $row = $DB->request([
            'FROM'  => Vulnerability::getTable(),
            'WHERE' => [
                'id'         => $equivalentIds,
                'is_current' => 1,
            ],
            'ORDER' => ['id DESC'],
            'LIMIT' => 1,
        ])->current();

        return is_array($row) && $row !== [] ? $row : null;
    }

    private function addCurrentDetectionFollowupIfChanged(int $ticketId, array $vulnerabilityFields): bool
    {
        if ($ticketId <= 0 || !class_exists(\ITILFollowup::class) || !$this->isTicketUsable($ticketId)) {
            return false;
        }

        $host = $this->loadHost((int) ($vulnerabilityFields['plugin_nessusglpi_hosts_id'] ?? 0));
        $scan = $this->loadScan((int) ($vulnerabilityFields['plugin_nessusglpi_scans_id'] ?? 0));
        $pluginDetails = $this->loadPluginDetails($vulnerabilityFields, $host?->fields ?? null, $scan?->fields ?? null);
        $snapshot = $this->buildDetectionSnapshot($vulnerabilityFields, $host?->fields ?? null, $scan?->fields ?? null, $pluginDetails);
        $hash = $this->buildDetectionFollowupHash($snapshot);

        if ($hash === '' || $this->ticketAlreadyHasDetectionHash($ticketId, $hash)) {
            return false;
        }

        $content = $this->buildDetectionFollowupContent($vulnerabilityFields, $snapshot, $hash);

        try {
            return (bool) (new \ITILFollowup())->add([
                'itemtype' => \Ticket::class,
                'items_id' => $ticketId,
                'content'  => $content,
            ]);
        } catch (Throwable $e) {
            return false;
        }
    }

    private function buildDetectionSnapshot(array $fields, ?array $hostFields, ?array $scanFields, ?array $pluginDetails): array
    {
        $details = $this->normalizePluginDetails($pluginDetails);
        $riskInformation = $details['risk_information'];
        $pluginInformation = $details['plugin_information'];
        $vulnInformation = $details['vuln_information'];

        $dbCvss = ((float) ($fields['cvss_base_score'] ?? 0)) > 0 ? (string) $fields['cvss_base_score'] : '';

        return [
            'schema'                   => 'nessusglpi-detection-v1',
            'vuln_key'                 => (string) ($fields['vuln_key'] ?? ''),
            'plugin_id'                => $this->firstNonEmpty([$details['plugin_id'], $fields['plugin_id_nessus'] ?? null]),
            'plugin_name'              => $this->cleanText($this->firstNonEmpty([$details['plugin_name'], $fields['plugin_name'] ?? null])),
            'severity'                 => (int) ($fields['severity'] ?? 0),
            'severity_label'           => $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), (int) ($fields['severity'] ?? 0)),
            'host'                     => $this->buildHostLabel($hostFields),
            'scan_id'                  => (string) ($scanFields['scan_id'] ?? ''),
            'scan_name'                => $this->cleanText((string) ($scanFields['name'] ?? '')),
            'port'                     => $this->firstNonEmpty([$details['port'], $fields['port'] ?? null]),
            'protocol'                 => $this->firstNonEmpty([$details['protocol'], $fields['protocol'] ?? null]),
            'cve'                      => $this->firstNonEmpty([$details['cve'], $fields['cve'] ?? null]),
            'see_also'                 => $details['see_also'],
            'synopsis'                 => $this->firstNonEmpty([$details['synopsis'], $fields['synopsis'] ?? null]),
            'description'              => $this->firstNonEmpty([$details['description'], $fields['description'] ?? null]),
            'solution'                 => $this->firstNonEmpty([$details['solution'], $fields['solution'] ?? null]),
            'plugin_output'            => $this->firstNonEmpty([$details['plugin_output'], $fields['plugin_output'] ?? null]),
            'risk_factor'              => $this->firstNonEmpty([$riskInformation['risk_factor'] ?? null, $fields['risk_factor'] ?? null]),
            'cvss_base_score'          => $this->firstNonEmpty([$riskInformation['cvss_base_score'] ?? null, $dbCvss]),
            'cvss3_base_score'         => $this->firstNonEmpty([$riskInformation['cvss3_base_score'] ?? null]),
            'vpr_score'                => $details['vpr_score'],
            'exploit_available'        => $this->firstNonEmpty([$vulnInformation['exploit_available'] ?? null]),
            'patch_publication_date'   => $this->firstNonEmpty([$vulnInformation['patch_publication_date'] ?? null]),
            'plugin_publication_date'  => $this->firstNonEmpty([$pluginInformation['plugin_publication_date'] ?? null]),
            'plugin_modification_date' => $this->firstNonEmpty([$pluginInformation['plugin_modification_date'] ?? null]),
            'cpe'                      => $this->firstNonEmpty([$vulnInformation['cpe'] ?? null]),
            'outputs'                  => $details['outputs'],
        ];
    }

    private function buildDetectionFollowupHash(array $snapshot): string
    {
        $normalized = $this->normalizeSnapshotValue($snapshot);
        $encoded = json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        return is_string($encoded) ? sha1($encoded) : '';
    }

    private function buildDetectionFollowupContent(array $fields, array $snapshot, string $hash): string
    {
        $when = date('Y-m-d H:i:s');
        $portProtocol = $this->joinPortProtocol((string) ($snapshot['port'] ?? ''), (string) ($snapshot['protocol'] ?? ''));
        $name = $this->cleanText((string) ($snapshot['plugin_name'] ?? '')) ?: __('Nessus vulnerability', 'nessusglpi');
        $detailsUrl = $this->buildVulnerabilityDetailsUrl((int) ($fields['id'] ?? 0));

        $html = [];
        $html[] = $this->detectionHashMarker($hash);
        $html[] = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">';
        $html[] = '<div style="padding:12px 16px; background:#eff6ff; border-left:4px solid #2563eb; border-radius:6px; color:#1e3a8a; font-size:14px; line-height:1.55;">'
            . '<strong>' . htmlspecialchars(__('Vulnerability still detected', 'nessusglpi'), ENT_QUOTES) . '</strong><br>'
            . htmlspecialchars(
                sprintf(
                    __('The latest Nessus synchronization (%s) still reports this finding. The evidence below was recorded automatically because the detection details changed or had not been recorded before.', 'nessusglpi'),
                    $when
                ),
                ENT_QUOTES
            )
            . '</div>';

        $html[] = $this->renderTicketCallout(__('Target & context', 'nessusglpi'), [
            __('Host', 'nessusglpi')      => (string) ($snapshot['host'] ?? ''),
            __('Scan', 'nessusglpi')      => (string) ($snapshot['scan_name'] ?? ''),
            __('Plugin ID', 'nessusglpi') => (string) ($snapshot['plugin_id'] ?? ''),
            __('Scan ID', 'nessusglpi')   => (string) ($snapshot['scan_id'] ?? ''),
            __('Port', 'nessusglpi')      => $portProtocol,
            __('First seen', 'nessusglpi') => $this->cleanText((string) ($fields['first_seen_at'] ?? '')),
            __('Last seen', 'nessusglpi') => $this->cleanText((string) ($fields['last_seen_at'] ?? '')),
        ]);

        if ($detailsUrl !== '') {
            $html[] = $this->renderTicketSection(__('GLPI details', 'nessusglpi'), $this->renderTicketLinkCard(
                $detailsUrl,
                __('Open vulnerability details', 'nessusglpi'),
                __('This link opens the same Details view used by the scan list.', 'nessusglpi')
            ));
        }

        $html[] = $this->renderTicketSection(__('Detection', 'nessusglpi'), $this->renderTicketBlockquote($name));

        if ((string) ($snapshot['synopsis'] ?? '') !== '') {
            $html[] = $this->renderTicketSection(__('Synopsis', 'nessusglpi'), $this->renderTicketBlockquote((string) $snapshot['synopsis']));
        }

        if ((string) ($snapshot['description'] ?? '') !== '') {
            $html[] = $this->renderTicketSection(__('Description'), $this->renderTicketProse((string) $snapshot['description']));
        }

        if ((string) ($snapshot['solution'] ?? '') !== '') {
            $html[] = $this->renderTicketSection(
                __('Recommended solution', 'nessusglpi'),
                $this->renderTicketHighlight((string) $snapshot['solution'], '#198754')
            );
        }

        $cveList = $this->extractCveList((string) ($snapshot['cve'] ?? ''));
        if ($cveList !== []) {
            $html[] = $this->renderTicketSection(__('Related CVEs', 'nessusglpi'), $this->renderCveList($cveList));
        }

        $seeAlso = is_array($snapshot['see_also'] ?? null) ? $snapshot['see_also'] : [];
        if ($seeAlso !== []) {
            $html[] = $this->renderTicketSection(__('See also', 'nessusglpi'), $this->renderExternalLinkList($seeAlso));
        }

        $riskRows = array_filter([
            'CVSS v2'                              => (string) ($snapshot['cvss_base_score'] ?? ''),
            'CVSS v3'                              => (string) ($snapshot['cvss3_base_score'] ?? ''),
            'VPR'                                  => (string) ($snapshot['vpr_score'] ?? ''),
            __('Risk factor', 'nessusglpi')        => (string) ($snapshot['risk_factor'] ?? ''),
            __('Exploit available', 'nessusglpi')  => (string) ($snapshot['exploit_available'] ?? ''),
            __('Patch publication date', 'nessusglpi') => (string) ($snapshot['patch_publication_date'] ?? ''),
        ], static fn ($value): bool => trim((string) $value) !== '');
        if ($riskRows !== []) {
            $html[] = $this->renderTicketSection(__('Risk assessment', 'nessusglpi'), $this->renderTicketTable($riskRows));
        }

        if ((string) ($snapshot['plugin_output'] ?? '') !== '') {
            $html[] = $this->renderTicketSection(__('Plugin output', 'nessusglpi'), $this->renderTicketCodeBlock((string) $snapshot['plugin_output']));
        }

        $portsTable = is_array($snapshot['outputs'] ?? null) ? $this->renderPortsTable($snapshot['outputs']) : '';
        if ($portsTable === '' && $portProtocol !== '') {
            $portsTable = $this->renderTicketTable([
                __('Port', 'nessusglpi')     => (string) ($snapshot['port'] ?? ''),
                __('Protocol', 'nessusglpi') => strtoupper((string) ($snapshot['protocol'] ?? '')),
            ]);
        }
        if ($portsTable !== '') {
            $html[] = $this->renderTicketSection(__('Affected ports', 'nessusglpi'), $portsTable);
        }

        $pluginMetaRows = array_filter([
            __('Published', 'nessusglpi') => (string) ($snapshot['plugin_publication_date'] ?? ''),
            __('Modified', 'nessusglpi')  => (string) ($snapshot['plugin_modification_date'] ?? ''),
            'CPE'                         => (string) ($snapshot['cpe'] ?? ''),
        ], static fn ($value): bool => trim((string) $value) !== '');
        if ($pluginMetaRows !== []) {
            $html[] = $this->renderTicketSection(__('Plugin metadata', 'nessusglpi'), $this->renderTicketTable($pluginMetaRows));
        }

        $html[] = $this->renderTicketFooter();
        $html[] = '</div>';

        return implode("\n", $html);
    }

    private function appendDetectionHashMarker(string $content, string $hash): string
    {
        if ($hash === '' || str_contains($content, 'nessusglpi-detection-hash:' . $hash)) {
            return $content;
        }

        return $this->detectionHashMarker($hash) . "\n" . $content;
    }

    private function detectionHashMarker(string $hash): string
    {
        return '<span style="display:none">nessusglpi-detection-hash:' . htmlspecialchars($hash, ENT_QUOTES) . '</span>';
    }

    private function ticketAlreadyHasDetectionHash(int $ticketId, string $hash): bool
    {
        global $DB;

        if ($ticketId <= 0 || $hash === '') {
            return false;
        }

        $needle = 'nessusglpi-detection-hash:' . $hash;

        $ticket = new \Ticket();
        if ($ticket->getFromDB($ticketId) && str_contains((string) ($ticket->fields['content'] ?? ''), $needle)) {
            return true;
        }

        if (!class_exists(\ITILFollowup::class)) {
            return false;
        }

        $iterator = $DB->request([
            'SELECT' => ['id', 'content'],
            'FROM'   => \ITILFollowup::getTable(),
            'WHERE'  => [
                'itemtype' => \Ticket::class,
                'items_id' => $ticketId,
            ],
            'ORDER' => ['id DESC'],
            'LIMIT' => 100,
        ]);

        foreach ($iterator as $row) {
            if (str_contains((string) ($row['content'] ?? ''), $needle)) {
                return true;
            }
        }

        return false;
    }

    private function normalizeSnapshotValue($value)
    {
        if (is_array($value)) {
            $normalized = [];
            foreach ($value as $key => $item) {
                $normalized[$key] = $this->normalizeSnapshotValue($item);
            }

            if ($this->isAssociativeArray($normalized)) {
                ksort($normalized);
            }

            return $normalized;
        }

        if (is_bool($value)) {
            return $value ? '1' : '0';
        }

        if ($value === null) {
            return '';
        }

        if (is_scalar($value)) {
            return trim((string) $value);
        }

        return '';
    }

    private function isAssociativeArray(array $value): bool
    {
        if ($value === []) {
            return false;
        }

        return array_keys($value) !== range(0, count($value) - 1);
    }

    private function findExistingVulnerabilityTicket(array $vulnerabilityFields, ?array $hostFields): ?int
    {
        global $DB;

        $equivalentIds = Vulnerability::getEquivalentVulnerabilityIds($vulnerabilityFields);
        if ($equivalentIds !== []) {
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
        }

        return TicketMemory::findVulnerabilityTicketId($vulnerabilityFields, $hostFields);
    }

    private function findExistingGroupedVulnerabilityTicket(array $groupRows): ?int
    {
        foreach ($groupRows as $row) {
            $ticketId = $this->findTicketLinkedDirectlyToVulnerability((int) ($row['id'] ?? 0));
            if ($ticketId !== null) {
                return $ticketId;
            }
        }

        foreach ($groupRows as $row) {
            $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
            $ticketId = TicketMemory::findVulnerabilityTicketId($row, $host?->fields ?? null);
            if ($ticketId !== null) {
                return $ticketId;
            }
        }

        return null;
    }

    /**
     * Look for a parent ticket that already represents the given vulnerability group.
     *
     * Strategy:
     *   1. Find any ticket linked to any vulnerability in the group.
     *   2. If that ticket is a SON_OF another ticket → return the parent (the grandparent).
     *   3. Else, if that ticket is a PARENT_OF other tickets → it already is a parent → return it.
     *   4. Otherwise return null (no parent structure yet).
     */
    private function findExistingGroupParentTicket(array $groupRows): ?int
    {
        $seen = [];

        foreach ($groupRows as $row) {
            $ticketId = $this->findTicketLinkedDirectlyToVulnerability((int) ($row['id'] ?? 0));
            if ($ticketId === null || isset($seen[$ticketId])) {
                continue;
            }
            $seen[$ticketId] = true;

            $parentOfThis = $this->findParentTicketId($ticketId);
            if ($parentOfThis !== null && $this->isTicketUsable($parentOfThis)) {
                return $parentOfThis;
            }

            if ($this->ticketHasChildren($ticketId) && $this->isTicketUsable($ticketId)) {
                return $ticketId;
            }
        }

        foreach ($groupRows as $row) {
            $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
            $ticketId = TicketMemory::findVulnerabilityTicketId($row, $host?->fields ?? null);
            if ($ticketId === null || isset($seen[$ticketId])) {
                continue;
            }
            $seen[$ticketId] = true;

            $parentOfThis = $this->findParentTicketId($ticketId);
            if ($parentOfThis !== null && $this->isTicketUsable($parentOfThis)) {
                return $parentOfThis;
            }

            if ($this->ticketHasChildren($ticketId) && $this->isTicketUsable($ticketId)) {
                return $ticketId;
            }
        }

        return null;
    }

    private function findParentTicketId(int $ticketId): ?int
    {
        global $DB;

        if ($ticketId <= 0) {
            return null;
        }

        $row = $DB->request([
            'FROM'  => 'glpi_tickets_tickets',
            'WHERE' => [
                'tickets_id_1' => $ticketId,
                'link'         => \CommonITILObject_CommonITILObject::SON_OF,
            ],
            'LIMIT' => 1,
        ])->current();

        if (!$row) {
            return null;
        }

        return (int) ($row['tickets_id_2'] ?? 0) ?: null;
    }

    private function ticketHasChildren(int $ticketId): bool
    {
        global $DB;

        if ($ticketId <= 0) {
            return false;
        }

        $row = $DB->request([
            'FROM'  => 'glpi_tickets_tickets',
            'WHERE' => [
                'tickets_id_2' => $ticketId,
                'link'         => \CommonITILObject_CommonITILObject::SON_OF,
            ],
            'LIMIT' => 1,
        ])->current();

        return $row !== null && !empty($row);
    }

    /**
     * @return array<string, array> Map of host-key → representative row (one row per affected host).
     */
    private function dedupGroupRowsByHost(array $groupRows): array
    {
        $byHost = [];

        foreach ($groupRows as $row) {
            $hostKey = $this->buildAffectedTargetKey($row);
            if (isset($byHost[$hostKey])) {
                continue;
            }
            $byHost[$hostKey] = $row;
        }

        return $byHost;
    }

    /**
     * Create the Ticket_Ticket SON_OF link from $sonId to $parentId (no-op if it already exists).
     */
    private function linkTicketsAsSon(int $sonId, int $parentId): void
    {
        global $DB;

        if ($sonId <= 0 || $parentId <= 0 || $sonId === $parentId) {
            return;
        }

        $existing = $DB->request([
            'FROM'  => 'glpi_tickets_tickets',
            'WHERE' => [
                'OR' => [
                    [
                        'tickets_id_1' => $sonId,
                        'tickets_id_2' => $parentId,
                    ],
                    [
                        'tickets_id_1' => $parentId,
                        'tickets_id_2' => $sonId,
                    ],
                ],
            ],
            'LIMIT' => 1,
        ])->current();

        if ($existing) {
            return;
        }

        $rel = new \Ticket_Ticket();
        $rel->add([
            'tickets_id_1' => $sonId,
            'tickets_id_2' => $parentId,
            'link'         => \CommonITILObject_CommonITILObject::SON_OF,
        ]);
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

    /** Heuristic OS family from plugin name + host names. */
    private function detectOsFamilyLabel(string $signal): string
    {
        if (preg_match('/linux|ubuntu|debian|centos|red\s?hat|rhel|rocky|alma|suse|sles|fedora|oracle\s+linux|amazon\s+linux|alpine/i', $signal)) {
            return '🐧 Linux';
        }
        if (preg_match('/windows|microsoft|\bkb\d|\.net\b|win32|win64/i', $signal)) {
            return '🪟 Windows';
        }
        return '—';
    }

    /** GLPI asset link status for a Nessus host record. */
    private function glpiLinkLabel(?array $hostFields): string
    {
        $hostFields = $hostFields ?? [];
        if (!empty($hostFields['items_id']) && !empty($hostFields['itemtype']) && class_exists((string) $hostFields['itemtype'])) {
            $itemtype = (string) $hostFields['itemtype'];
            $obj = new $itemtype();
            if ($obj->getFromDB((int) $hostFields['items_id'])) {
                $name = trim((string) ($obj->fields['name'] ?? ''));
                return '✅ ' . ($name !== '' ? $name : '#' . (int) $hostFields['items_id']);
            }
        }
        return '⚠️ ' . __('Não inventariado (sem vínculo)', 'nessusglpi');
    }

    private function buildVulnerabilityContent(array $fields, ?array $hostFields, ?array $scanFields, ?array $pluginDetails): string
    {
        $details = $this->normalizePluginDetails($pluginDetails);
        $severity = (int) ($fields['severity'] ?? 0);
        $severityLabel = $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), $severity);
        $severityMeta = $this->severityHtmlMeta($severity, $severityLabel);

        $name = $this->cleanText($this->firstNonEmpty([$details['plugin_name'], $fields['plugin_name'] ?? null])) ?: __('Nessus vulnerability', 'nessusglpi');
        $hostLabel = $this->buildHostLabel($hostFields);
        $detailsUrl = $this->buildVulnerabilityDetailsUrl((int) ($fields['id'] ?? 0));

        $cve = $this->firstNonEmpty([$details['cve'], $fields['cve'] ?? null]);
        $port = $this->firstNonEmpty([$details['port'], $fields['port'] ?? null]);
        $protocol = $this->firstNonEmpty([$details['protocol'], $fields['protocol'] ?? null]);
        $synopsis = $this->firstNonEmpty([$details['synopsis'], $fields['synopsis'] ?? null]);
        $description = $this->firstNonEmpty([$details['description'], $fields['description'] ?? null]);
        $solution = $this->firstNonEmpty([$details['solution'], $fields['solution'] ?? null]);
        $pluginOutput = $this->firstNonEmpty([$details['plugin_output'], $fields['plugin_output'] ?? null]);

        $riskInformation = $details['risk_information'];
        $pluginInformation = $details['plugin_information'];
        $vulnInformation = $details['vuln_information'];

        $html = [];
        $html[] = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">';
        $html[] = $this->renderTicketHero($severityMeta, $name, '🛡️ ' . __('Vulnerability detected by Nessus', 'nessusglpi'));

        $hf        = $hostFields ?? [];
        $hostIp    = $this->cleanText((string) ($hf['ip'] ?? ''));
        $osLabel   = $this->detectOsFamilyLabel($name . ' ' . (string) ($hf['fqdn'] ?? '') . ' ' . (string) ($hf['hostname'] ?? ''));
        $linkLabel = $this->glpiLinkLabel($hostFields);

        $html[] = $this->renderTicketCallout('🎯 ' . __('Target & context', 'nessusglpi'), [
            '🖥️ ' . __('Host', 'nessusglpi')          => $hostLabel,
            '🌐 IP'                                    => $hostIp !== '' ? $hostIp : '—',
            '💻 ' . __('Sistema (detectado)', 'nessusglpi') => $osLabel,
            '🔗 ' . __('Vínculo GLPI', 'nessusglpi')   => $linkLabel,
            '🗂️ ' . __('Scan', 'nessusglpi')          => $this->cleanText((string) ($scanFields['name'] ?? '')),
            '📌 ' . __('Plugin ID', 'nessusglpi')      => $this->firstNonEmpty([$details['plugin_id'], $fields['plugin_id_nessus'] ?? null]),
            '🔍 ' . __('Scan ID', 'nessusglpi')        => (string) ($scanFields['scan_id'] ?? ''),
            '🚪 ' . __('Port', 'nessusglpi')           => $this->joinPortProtocol($port, $protocol),
            '📅 ' . __('Last seen', 'nessusglpi')      => $this->cleanText((string) ($fields['last_seen_at'] ?? '')),
            '📅 ' . __('First seen', 'nessusglpi')     => $this->cleanText((string) ($fields['first_seen_at'] ?? '')),
        ]);

        if ($detailsUrl !== '') {
            $html[] = $this->renderTicketSection('🔎 ' . __('GLPI details', 'nessusglpi'), $this->renderTicketLinkCard(
                $detailsUrl,
                __('Open vulnerability details', 'nessusglpi'),
                __('This is the same Details view available from the scan vulnerability list.', 'nessusglpi')
            ));
        }

        if ($synopsis !== '') {
            $html[] = $this->renderTicketSection('📄 ' . __('Synopsis', 'nessusglpi'), $this->renderTicketBlockquote($synopsis));
        }

        if ($description !== '') {
            $html[] = $this->renderTicketSection('🔎 ' . __('Description'), $this->renderTicketProse($description));
        }

        if ($solution !== '') {
            $html[] = $this->renderTicketSection(
                '🛠️ ' . __('Recommended solution', 'nessusglpi'),
                $this->renderTicketHighlight($solution, '#198754')
            );
        }

        $cveList = $this->extractCveList($cve);
        if ($cveList !== []) {
            $html[] = $this->renderTicketSection('🔗 ' . __('Related CVEs', 'nessusglpi'), $this->renderCveList($cveList));
        }

        if ($details['see_also'] !== []) {
            $html[] = $this->renderTicketSection('🔗 ' . __('See also', 'nessusglpi'), $this->renderExternalLinkList($details['see_also']));
        }

        // Fall back to the values stored in the DB when the live Nessus detail is unavailable.
        $dbCvss = ((float) ($fields['cvss_base_score'] ?? 0)) > 0 ? (string) $fields['cvss_base_score'] : null;
        $riskRows = [
            'CVSS v2'                                    => $this->firstNonEmpty([$riskInformation['cvss_base_score'] ?? null]),
            'CVSS v3'                                    => $this->firstNonEmpty([$riskInformation['cvss3_base_score'] ?? null]),
            'CVSS'                                       => $this->firstNonEmpty([$dbCvss]),
            'VPR'                                        => $details['vpr_score'],
            __('Risk factor', 'nessusglpi')              => $this->firstNonEmpty([$riskInformation['risk_factor'] ?? null, $fields['risk_factor'] ?? null]),
            __('Exploit available', 'nessusglpi')        => $this->firstNonEmpty([$vulnInformation['exploit_available'] ?? null]),
            __('Patch publication date', 'nessusglpi')   => $this->firstNonEmpty([$vulnInformation['patch_publication_date'] ?? null]),
        ];
        // Avoid showing both a generic "CVSS" and the versioned ones at the same time.
        if (($riskRows['CVSS v2'] ?? '') !== '' || ($riskRows['CVSS v3'] ?? '') !== '') {
            $riskRows['CVSS'] = '';
        }
        $riskRowsFiltered = array_filter($riskRows, static fn ($v) => $v !== '');
        if ($riskRowsFiltered !== []) {
            $html[] = $this->renderTicketSection('📊 ' . __('Risk assessment', 'nessusglpi'), $this->renderTicketTable($riskRowsFiltered));
        }

        if ($pluginOutput !== '') {
            $html[] = $this->renderTicketSection('📤 ' . __('Plugin output', 'nessusglpi'), $this->renderTicketCodeBlock($pluginOutput));
        }

        $portsTable = '';
        if ($details['outputs'] !== []) {
            $portsTable = $this->renderPortsTable($details['outputs']);
        }
        if ($portsTable === '' && $this->joinPortProtocol($port, $protocol) !== '') {
            $portsTable = $this->renderTicketTable([
                '🚪 ' . __('Port', 'nessusglpi')     => $port !== '' ? $port : '—',
                '📡 ' . __('Protocol', 'nessusglpi') => $protocol !== '' ? strtoupper($protocol) : '—',
            ]);
        }
        if ($portsTable !== '') {
            $html[] = $this->renderTicketSection('📡 ' . __('Affected ports', 'nessusglpi'), $portsTable);
        }

        $pluginMetaRows = [
            __('Published', 'nessusglpi')               => $this->firstNonEmpty([$pluginInformation['plugin_publication_date'] ?? null]),
            __('Modified', 'nessusglpi')                => $this->firstNonEmpty([$pluginInformation['plugin_modification_date'] ?? null]),
            'CPE'                                       => $this->firstNonEmpty([$vulnInformation['cpe'] ?? null]),
        ];
        $pluginMetaFiltered = array_filter($pluginMetaRows, static fn ($v) => $v !== '');
        if ($pluginMetaFiltered !== []) {
            $html[] = $this->renderTicketSection('📚 ' . __('Plugin metadata', 'nessusglpi'), $this->renderTicketTable($pluginMetaFiltered));
        }

        if ($details['_load_error'] !== '') {
            $html[] = $this->renderTicketSection(
                '⚠️ ' . __('Nessus detail error', 'nessusglpi'),
                $this->renderTicketHighlight($details['_load_error'], '#dc3545')
            );
        }

        $html[] = $this->renderTicketFooter();
        $html[] = '</div>';

        return implode("\n", $html);
    }

    private function buildGroupedVulnerabilityContent(array $fields, array $groupRows, ?array $pluginDetails): string
    {
        $details = $this->normalizePluginDetails($pluginDetails);
        $severity = (int) ($fields['severity'] ?? 0);
        $severityLabel = $this->normalizeSeverityLabel((string) ($fields['severity_label'] ?? ''), $severity);
        $severityMeta = $this->severityHtmlMeta($severity, $severityLabel);

        $name = $this->cleanText($this->firstNonEmpty([$details['plugin_name'], $fields['plugin_name'] ?? null])) ?: __('Nessus vulnerability', 'nessusglpi');
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
        $scanIds = array_values(array_unique($scanIds));

        $cve = $this->firstNonEmpty([$details['cve'], $fields['cve'] ?? null]);
        $port = $this->firstNonEmpty([$details['port'], $fields['port'] ?? null]);
        $protocol = $this->firstNonEmpty([$details['protocol'], $fields['protocol'] ?? null]);
        $synopsis = $this->firstNonEmpty([$details['synopsis'], $fields['synopsis'] ?? null]);
        $description = $this->firstNonEmpty([$details['description'], $fields['description'] ?? null]);
        $solution = $this->firstNonEmpty([$details['solution'], $fields['solution'] ?? null]);
        $pluginOutput = $this->firstNonEmpty([$details['plugin_output'], $fields['plugin_output'] ?? null]);

        $riskInformation = $details['risk_information'];
        $vulnInformation = $details['vuln_information'];

        $html = [];
        $html[] = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">';
        $html[] = $this->renderTicketHero(
            $severityMeta,
            $name,
            '🛡️ ' . sprintf(__('Vulnerability affecting %d assets', 'nessusglpi'), count($targets))
        );

        $html[] = '<div style="margin:0 0 22px 0; padding:12px 16px; background:#eff6ff; border-left:4px solid #2563eb; border-radius:6px; color:#1e3a8a; font-size:13px; line-height:1.5;">'
            . '<strong>🌳 ' . htmlspecialchars(__('Parent ticket', 'nessusglpi'), ENT_QUOTES) . '</strong> — '
            . htmlspecialchars(
                sprintf(
                    __('One child ticket has been linked per affected host (%d in total). Check the “Linked tickets” panel for the breakdown.', 'nessusglpi'),
                    count($targets)
                ),
                ENT_QUOTES
            )
            . '</div>';

        $html[] = $this->renderTicketSection(
            '🎯 ' . __('Affected assets', 'nessusglpi') . ' <span style="color:#6c757d; font-weight:400;">(' . count($targets) . ')</span>',
            $this->renderTargetList($targets)
        );

        $detailLinks = $this->renderVulnerabilityDetailLinks($groupRows);
        if ($detailLinks !== '') {
            $html[] = $this->renderTicketSection('🔎 ' . __('GLPI details', 'nessusglpi'), $detailLinks);
        }

        $html[] = $this->renderTicketCallout('📌 ' . __('Vulnerability metadata', 'nessusglpi'), [
            __('Plugin ID', 'nessusglpi')       => $this->firstNonEmpty([$details['plugin_id'], $fields['plugin_id_nessus'] ?? null]),
            __('Scan IDs', 'nessusglpi')        => $scanIds === [] ? '' : implode(', ', $scanIds),
            '🚪 ' . __('Port', 'nessusglpi')    => $this->joinPortProtocol($port, $protocol),
        ]);

        if ($synopsis !== '') {
            $html[] = $this->renderTicketSection('📄 ' . __('Synopsis', 'nessusglpi'), $this->renderTicketBlockquote($synopsis));
        }

        if ($description !== '') {
            $html[] = $this->renderTicketSection('🔎 ' . __('Description'), $this->renderTicketProse($description));
        }

        if ($solution !== '') {
            $html[] = $this->renderTicketSection(
                '🛠️ ' . __('Recommended solution', 'nessusglpi'),
                $this->renderTicketHighlight($solution, '#198754')
            );
        }

        $cveList = $this->extractCveList($cve);
        if ($cveList !== []) {
            $html[] = $this->renderTicketSection('🔗 ' . __('Related CVEs', 'nessusglpi'), $this->renderCveList($cveList));
        }

        if ($details['see_also'] !== []) {
            $html[] = $this->renderTicketSection('🔗 ' . __('See also', 'nessusglpi'), $this->renderExternalLinkList($details['see_also']));
        }

        $dbCvssGroup = ((float) ($fields['cvss_base_score'] ?? 0)) > 0 ? (string) $fields['cvss_base_score'] : null;
        $riskRows = array_filter([
            'CVSS v2'                                    => $this->firstNonEmpty([$riskInformation['cvss_base_score'] ?? null]),
            'CVSS v3'                                    => $this->firstNonEmpty([$riskInformation['cvss3_base_score'] ?? null]),
            'CVSS'                                       => $this->firstNonEmpty([$dbCvssGroup]),
            'VPR'                                        => $details['vpr_score'],
            __('Risk factor', 'nessusglpi')              => $this->firstNonEmpty([$riskInformation['risk_factor'] ?? null, $fields['risk_factor'] ?? null]),
            __('Exploit available', 'nessusglpi')        => $this->firstNonEmpty([$vulnInformation['exploit_available'] ?? null]),
        ], static fn ($v) => $v !== '');
        if (isset($riskRows['CVSS v2']) || isset($riskRows['CVSS v3'])) {
            unset($riskRows['CVSS']);
        }
        if ($riskRows !== []) {
            $html[] = $this->renderTicketSection('📊 ' . __('Risk assessment', 'nessusglpi'), $this->renderTicketTable($riskRows));
        }

        if ($this->joinPortProtocol($port, $protocol) !== '') {
            $html[] = $this->renderTicketSection('📡 ' . __('Affected ports', 'nessusglpi'), $this->renderTicketTable([
                '🚪 ' . __('Port', 'nessusglpi')     => $port !== '' ? $port : '—',
                '📡 ' . __('Protocol', 'nessusglpi') => $protocol !== '' ? strtoupper($protocol) : '—',
            ]));
        }

        if ($pluginOutput !== '') {
            $html[] = $this->renderTicketSection('📤 ' . __('Sample output', 'nessusglpi'), $this->renderTicketCodeBlock($pluginOutput));
        }

        if ($details['_load_error'] !== '') {
            $html[] = $this->renderTicketSection(
                '⚠️ ' . __('Nessus detail error', 'nessusglpi'),
                $this->renderTicketHighlight($details['_load_error'], '#dc3545')
            );
        }

        $html[] = $this->renderTicketFooter();
        $html[] = '</div>';

        return implode("\n", $html);
    }

    private function buildHostContent(array $fields): string
    {
        $matchStatus = strtolower(trim((string) ($fields['match_status'] ?? '')));
        $statusEmoji = match ($matchStatus) {
            'matched', 'ok', 'success' => '✅',
            'pending', 'unmatched', 'unknown', '' => '⚠️',
            'failed', 'error', 'rejected' => '❌',
            default => '⚠️',
        };

        $hostLabel = $this->buildHostLabel($fields);

        $html = [];
        $html[] = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">';

        $heroMeta = [
            'background' => '#fff7ed',
            'border'     => '#fb923c',
            'color'      => '#9a3412',
            'icon'       => '🌐',
            'label'      => __('PENDING HOST', 'nessusglpi'),
        ];
        $html[] = $this->renderTicketHero($heroMeta, $hostLabel, '🌐 ' . __('Imported host without confirmed asset link', 'nessusglpi'));

        $html[] = $this->renderTicketCallout('📋 ' . __('Host details', 'nessusglpi'), [
            '🖥️ ' . __('Hostname', 'nessusglpi')        => (string) ($fields['hostname'] ?? ''),
            '🌐 FQDN'                                    => (string) ($fields['fqdn'] ?? ''),
            '📡 IP'                                      => (string) ($fields['ip'] ?? ''),
            $statusEmoji . ' ' . __('Match status', 'nessusglpi')  => (string) ($fields['match_status'] ?? ''),
        ]);

        $matchMessage = $this->cleanText((string) ($fields['match_message'] ?? ''));
        if ($matchMessage !== '') {
            $html[] = $this->renderTicketSection(
                '💬 ' . __('Match details', 'nessusglpi'),
                $this->renderTicketBlockquote($matchMessage)
            );
        }

        $html[] = '<div style="margin-top:20px; padding:14px 16px; background:#fef3c7; border-left:4px solid #f59e0b; border-radius:4px;">';
        $html[] = '<strong>⚠️ ' . htmlspecialchars(__('Action needed', 'nessusglpi'), ENT_QUOTES) . ':</strong> '
            . htmlspecialchars(__('Confirm whether this host corresponds to an existing GLPI asset, then update the asset matching configuration or register the asset manually.', 'nessusglpi'), ENT_QUOTES);
        $html[] = '</div>';

        $html[] = $this->renderTicketFooter();
        $html[] = '</div>';

        return implode("\n", $html);
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

    private function buildVulnerabilityDetailsUrl(int $vulnerabilityId): string
    {
        global $CFG_GLPI;

        if ($vulnerabilityId <= 0) {
            return '';
        }

        $path = '/plugins/nessusglpi/front/vulnerability.form.php?id=' . $vulnerabilityId;
        $urlBase = rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/');
        if ($urlBase !== '') {
            return $urlBase . $path;
        }

        $rootDoc = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/');
        return $rootDoc . $path;
    }

    private function collectAffectedHostLabels(array $groupRows): array
    {
        $labels = [];

        foreach ($groupRows as $row) {
            $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
            $label = $host !== null ? $this->buildHostLabel($host->fields) : $this->buildAffectedTargetLabel($row);
            if ($label === '') {
                continue;
            }

            $labels[$label] = $label;
        }

        return array_values($labels);
    }

    private function buildGroupedDetailLines(array $groupRows): array
    {
        $lines = [];

        foreach ($groupRows as $row) {
            $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
            $label = $host !== null ? $this->buildHostLabel($host->fields) : $this->buildAffectedTargetLabel($row);
            $lines[] = sprintf(__('More information for host %s', 'nessusglpi'), $label) . ' - ' . $this->buildVulnerabilityDetailsUrl((int) ($row['id'] ?? 0));
        }

        return $lines;
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
        // Group by the vulnerability itself (Nessus plugin id) so the same finding
        // across several hosts produces ONE parent ticket + one child per host.
        $pluginId = trim((string) ($fields['plugin_id_nessus'] ?? ''));
        if ($pluginId !== '') {
            return sha1('plugin|' . $pluginId);
        }

        // Fallback when the Nessus plugin id is missing: name + severity.
        return sha1('name|' . strtolower(trim((string) ($fields['plugin_name'] ?? ''))) . '|' . (int) ($fields['severity'] ?? 0));
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

    /**
     * Returns severity visual metadata for ticket HTML hero (background, border, color, emoji, label).
     */
    private function severityHtmlMeta(int $severity, string $label): array
    {
        return match ($severity) {
            4 => [
                'background' => '#fef2f2',
                'border'     => '#8f233f',
                'color'      => '#8f233f',
                'icon'       => '💀',
                'label'      => __('CRITICAL', 'nessusglpi'),
            ],
            3 => [
                'background' => '#fff1f0',
                'border'     => '#d94f4f',
                'color'      => '#b91c1c',
                'icon'       => '🚨',
                'label'      => __('HIGH', 'nessusglpi'),
            ],
            2 => [
                'background' => '#fff7ed',
                'border'     => '#f6a14a',
                'color'      => '#9a3412',
                'icon'       => '⚠️',
                'label'      => __('MEDIUM', 'nessusglpi'),
            ],
            1 => [
                'background' => '#fefce8',
                'border'     => '#f2d15c',
                'color'      => '#854d0e',
                'icon'       => '🟡',
                'label'      => __('LOW', 'nessusglpi'),
            ],
            default => [
                'background' => '#eff6ff',
                'border'     => '#6aa7df',
                'color'      => '#1e40af',
                'icon'       => '🔵',
                'label'      => $label !== '' ? strtoupper($label) : __('INFO', 'nessusglpi'),
            ],
        };
    }

    private function renderTicketHero(array $meta, string $title, string $subtitle): string
    {
        $bg = $meta['background'];
        $border = $meta['border'];
        $color = $meta['color'];
        $icon = $meta['icon'];
        $label = htmlspecialchars($meta['label'], ENT_QUOTES);
        $safeTitle = htmlspecialchars($title, ENT_QUOTES);
        $safeSubtitle = htmlspecialchars($subtitle, ENT_QUOTES);

        return '<div style="background:' . $bg . '; border:1px solid ' . $border . '40; border-left:5px solid ' . $border . '; padding:20px 24px; border-radius:12px; margin-bottom:24px; box-shadow:0 10px 26px -16px rgba(15,23,42,.4);">'
            . '<div style="display:inline-block; background:' . $border . '; color:#fff; font-weight:700; font-size:11px; letter-spacing:0.06em; text-transform:uppercase; padding:5px 13px; border-radius:999px; margin-bottom:12px; box-shadow:0 4px 10px -4px ' . $border . '80;">' . $icon . ' ' . $label . '</div>'
            . '<div style="font-size:12px; color:' . $color . '; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; margin-bottom:5px;">' . $safeSubtitle . '</div>'
            . '<h2 style="margin:0; font-size:22px; line-height:1.3; color:#0f172a; font-weight:700;">' . $safeTitle . '</h2>'
            . '</div>';
    }

    private function renderTicketSection(string $titleHtml, string $bodyHtml): string
    {
        return '<section style="margin:22px 0;">'
            . '<h3 style="font-size:16px; font-weight:700; color:#0f172a; margin:0 0 10px 0; padding-bottom:6px; border-bottom:1px solid #e5e7eb;">' . $titleHtml . '</h3>'
            . $bodyHtml
            . '</section>';
    }

    private function renderTicketCallout(string $titleHtml, array $rows): string
    {
        $rows = array_filter($rows, static fn ($v) => trim((string) $v) !== '');
        if ($rows === []) {
            return '';
        }

        $items = '';
        $i = 0;
        $count = count($rows);
        foreach ($rows as $label => $value) {
            $rowBg  = $i % 2 === 0 ? '#ffffff' : '#f8fafc';
            $border = $i === $count - 1 ? 'none' : '1px solid #eef2f6';
            $items .= '<tr style="background:' . $rowBg . ';">'
                . '<td style="padding:11px 18px; color:#64748b; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.04em; white-space:nowrap; vertical-align:top; width:180px; border-bottom:' . $border . ';">' . $label . '</td>'
                . '<td style="padding:11px 18px; color:#0f172a; font-size:14px; font-weight:600; vertical-align:top; border-bottom:' . $border . ';">' . htmlspecialchars((string) $value, ENT_QUOTES) . '</td>'
                . '</tr>';
            $i++;
        }

        return '<section style="margin:22px 0;">'
            . '<h3 style="font-size:16px; font-weight:700; color:#0f172a; margin:0 0 12px 0; display:flex; align-items:center; gap:8px;">' . $titleHtml . '</h3>'
            . '<div style="border:1px solid #e2e8f0; border-radius:12px; overflow:hidden; box-shadow:0 6px 18px -12px rgba(15,23,42,.25);">'
            . '<table style="border-collapse:collapse; width:100%;">'
            . $items
            . '</table>'
            . '</div>'
            . '</section>';
    }

    private function renderTicketBlockquote(string $text): string
    {
        return '<blockquote style="margin:0; padding:12px 16px; background:#f8fafc; border-left:3px solid #94a3b8; border-radius:4px; color:#334155; font-style:italic; line-height:1.55;">'
            . nl2br(htmlspecialchars($text, ENT_QUOTES))
            . '</blockquote>';
    }

    private function renderTicketProse(string $text): string
    {
        return '<div style="color:#1f2937; line-height:1.6; font-size:14px;">'
            . nl2br(htmlspecialchars($text, ENT_QUOTES))
            . '</div>';
    }

    private function renderTicketHighlight(string $text, string $accent): string
    {
        $bg = $accent === '#198754' ? '#ecfdf5' : ($accent === '#dc3545' ? '#fef2f2' : '#eff6ff');
        return '<div style="padding:12px 16px; background:' . $bg . '; border-left:3px solid ' . $accent . '; border-radius:4px; color:#0f172a; line-height:1.6; font-size:14px;">'
            . nl2br(htmlspecialchars($text, ENT_QUOTES))
            . '</div>';
    }

    private function renderTicketCodeBlock(string $text): string
    {
        return '<pre style="margin:0; padding:14px 16px; background:#0f172a; color:#e2e8f0; border-radius:6px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; line-height:1.55; overflow-x:auto; white-space:pre-wrap; word-break:break-word;">'
            . htmlspecialchars($text, ENT_QUOTES)
            . '</pre>';
    }

    private function renderTicketTable(array $rows): string
    {
        $items = '';
        foreach ($rows as $label => $value) {
            $items .= '<tr>'
                . '<th style="text-align:left; padding:8px 12px; background:#f1f5f9; color:#475569; font-size:13px; font-weight:600; border-bottom:1px solid #e2e8f0;">' . htmlspecialchars((string) $label, ENT_QUOTES) . '</th>'
                . '<td style="padding:8px 12px; color:#0f172a; font-size:14px; border-bottom:1px solid #e2e8f0;">' . htmlspecialchars((string) $value, ENT_QUOTES) . '</td>'
                . '</tr>';
        }
        return '<table style="border-collapse:collapse; width:100%; border:1px solid #e2e8f0; border-radius:6px; overflow:hidden;">'
            . $items
            . '</table>';
    }

    private function renderCveList(array $cves): string
    {
        $items = '';
        foreach ($cves as $cve) {
            $cve = trim((string) $cve);
            if ($cve === '') {
                continue;
            }
            $href = 'https://nvd.nist.gov/vuln/detail/' . rawurlencode($cve);
            $items .= '<a href="' . htmlspecialchars($href, ENT_QUOTES) . '" target="_blank" rel="noopener noreferrer" '
                . 'style="display:inline-block; margin:0 6px 6px 0; padding:5px 12px; background:#eff6ff; color:#1e40af; border:1px solid #bfdbfe; border-radius:6px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; font-weight:600; text-decoration:none;">'
                . '🔗 ' . htmlspecialchars($cve, ENT_QUOTES)
                . '</a>';
        }
        return '<div>' . $items . '</div>';
    }

    private function renderTicketLinkCard(string $url, string $label, string $description = ''): string
    {
        $url = trim($url);
        if ($url === '') {
            return '';
        }

        $safeUrl = htmlspecialchars($url, ENT_QUOTES);
        $html = '<div style="padding:12px 16px; background:#f8fafc; border:1px solid #dbeafe; border-left:3px solid #2563eb; border-radius:6px;">'
            . '<a href="' . $safeUrl . '" target="_blank" rel="noopener noreferrer" style="display:inline-block; color:#1d4ed8; font-weight:700; text-decoration:none;">'
            . htmlspecialchars($label, ENT_QUOTES)
            . '</a>';

        if ($description !== '') {
            $html .= '<div style="margin-top:4px; color:#475569; font-size:13px; line-height:1.45;">'
                . htmlspecialchars($description, ENT_QUOTES)
                . '</div>';
        }

        $html .= '<div style="margin-top:6px; color:#64748b; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; word-break:break-all;">'
            . $safeUrl
            . '</div>'
            . '</div>';

        return $html;
    }

    private function renderExternalLinkList(array $links): string
    {
        $items = '';
        foreach ($this->normalizeStringList($links) as $link) {
            $safeLabel = htmlspecialchars($link, ENT_QUOTES);
            if (filter_var($link, FILTER_VALIDATE_URL)) {
                $safeHref = htmlspecialchars($link, ENT_QUOTES);
                $items .= '<li style="margin:0 0 7px 0; color:#0f172a; word-break:break-all;">'
                    . '<a href="' . $safeHref . '" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8; text-decoration:none;">'
                    . $safeLabel
                    . '</a>'
                    . '</li>';
            } else {
                $items .= '<li style="margin:0 0 7px 0; color:#0f172a; word-break:break-word;">' . $safeLabel . '</li>';
            }
        }

        return $items === '' ? '' : '<ul style="margin:0; padding-left:18px;">' . $items . '</ul>';
    }

    private function renderVulnerabilityDetailLinks(array $groupRows): string
    {
        $items = '';
        $seen = [];

        foreach ($groupRows as $row) {
            $id = (int) ($row['id'] ?? 0);
            $url = $this->buildVulnerabilityDetailsUrl($id);
            if ($id <= 0 || $url === '' || isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;

            $host = $this->loadHost((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0));
            $label = $host !== null ? $this->buildHostLabel($host->fields) : $this->buildAffectedTargetLabel($row);
            $safeUrl = htmlspecialchars($url, ENT_QUOTES);
            $items .= '<li style="margin:0 0 8px 0; color:#0f172a; word-break:break-word;">'
                . htmlspecialchars($label, ENT_QUOTES)
                . ' - <a href="' . $safeUrl . '" target="_blank" rel="noopener noreferrer" style="color:#1d4ed8; text-decoration:none;">'
                . htmlspecialchars(__('Open details', 'nessusglpi'), ENT_QUOTES)
                . '</a>'
                . '<div style="margin-top:2px; color:#64748b; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; word-break:break-all;">'
                . $safeUrl
                . '</div>'
                . '</li>';
        }

        return $items === '' ? '' : '<ul style="margin:0; padding-left:18px;">' . $items . '</ul>';
    }

    private function renderTargetList(array $targets): string
    {
        if ($targets === []) {
            return '';
        }
        $items = '';
        foreach ($targets as $target) {
            $label = htmlspecialchars((string) ($target['label'] ?? ''), ENT_QUOTES);
            if ($label === '') {
                continue;
            }
            $items .= '<li style="padding:7px 12px; margin:0 0 4px 0; background:#f8fafc; border-left:3px solid #3b82f6; border-radius:4px; list-style:none; font-size:14px; color:#0f172a;">'
                . '🖥️ ' . $label
                . '</li>';
        }
        return '<ul style="margin:0; padding:0;">' . $items . '</ul>';
    }

    private function renderPortsTable(array $outputs): string
    {
        $rows = [];
        foreach ($outputs as $output) {
            if (!is_array($output)) {
                continue;
            }
            $ports = $output['ports'] ?? null;
            if (!is_array($ports)) {
                continue;
            }
            foreach ($ports as $portLabel => $hosts) {
                $hostLabels = [];
                if (is_array($hosts)) {
                    foreach ($hosts as $host) {
                        if (is_array($host)) {
                            $hostText = trim((string) ($host['hostname'] ?? $host['host'] ?? ''));
                            if ($hostText !== '') {
                                $hostLabels[] = $hostText;
                            }
                        }
                    }
                }
                $rows[] = [
                    'port'  => (string) $portLabel,
                    'hosts' => implode(', ', $hostLabels),
                ];
            }
        }

        if ($rows === []) {
            return '';
        }

        $body = '<thead><tr>'
            . '<th style="text-align:left; padding:8px 12px; background:#f1f5f9; color:#475569; font-size:13px; font-weight:600; border-bottom:1px solid #e2e8f0;">🚪 ' . htmlspecialchars(__('Port', 'nessusglpi'), ENT_QUOTES) . '</th>'
            . '<th style="text-align:left; padding:8px 12px; background:#f1f5f9; color:#475569; font-size:13px; font-weight:600; border-bottom:1px solid #e2e8f0;">🖥️ ' . htmlspecialchars(__('Hosts', 'nessusglpi'), ENT_QUOTES) . '</th>'
            . '</tr></thead><tbody>';
        foreach ($rows as $row) {
            $body .= '<tr>'
                . '<td style="padding:8px 12px; border-bottom:1px solid #e2e8f0; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px; color:#0f172a;">' . htmlspecialchars($row['port'], ENT_QUOTES) . '</td>'
                . '<td style="padding:8px 12px; border-bottom:1px solid #e2e8f0; font-size:14px; color:#0f172a;">' . htmlspecialchars($row['hosts'], ENT_QUOTES) . '</td>'
                . '</tr>';
        }
        $body .= '</tbody>';

        return '<table style="border-collapse:collapse; width:100%; border:1px solid #e2e8f0; border-radius:6px; overflow:hidden;">' . $body . '</table>';
    }

    private function renderTicketFooter(): string
    {
        return '<div style="margin-top:28px; padding-top:14px; border-top:1px solid #e5e7eb; color:#94a3b8; font-size:12px;">'
            . '🤖 ' . htmlspecialchars(__('Generated automatically by the Nessus Conector plugin', 'nessusglpi'), ENT_QUOTES)
            . ' · 🛡️ <strong>Tenable / Nessus</strong>'
            . '</div>';
    }

    private function cleanText(string $value): string
    {
        return trim($value);
    }

    /**
     * @param array<int, mixed> $candidates
     */
    private function firstNonEmpty(array $candidates): string
    {
        foreach ($candidates as $candidate) {
            if ($candidate === null) {
                continue;
            }
            if (is_array($candidate)) {
                $encoded = json_encode($candidate, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $text = trim((string) $encoded);
            } else {
                $text = trim((string) $candidate);
            }
            if ($text !== '') {
                return $text;
            }
        }
        return '';
    }

    private function joinPortProtocol(string $port, string $protocol): string
    {
        $port = trim($port);
        $protocol = trim($protocol);
        if ($port === '' && $protocol === '') {
            return '';
        }
        if ($port !== '' && $protocol !== '') {
            return $port . '/' . strtolower($protocol);
        }
        return $port !== '' ? $port : strtolower($protocol);
    }

    /**
     * @return array<int, string>
     */
    private function extractCveList(string $value): array
    {
        $value = trim($value);
        if ($value === '') {
            return [];
        }
        $parts = preg_split('/[\s,;]+/', $value) ?: [];
        $cves = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part !== '' && stripos($part, 'CVE-') === 0) {
                $cves[strtoupper($part)] = true;
            }
        }
        return array_keys($cves);
    }
}
