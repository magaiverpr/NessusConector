<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

/**
 * Relatorio de cobertura do Nessus: computadores (ativos no GLPI) que NAO
 * possuem host casado no Nessus, restrito a maquinas virtuais cujo sistema
 * operacional seja Linux ou Windows Server — o publico onde costuma ser mais
 * facil identificar onde o scanner ainda nao chegou.
 *
 * Deteccao de VM: casa o nome do TIPO, MODELO ou FABRICANTE do computador
 * contra assinaturas conhecidas de hypervisor (VMware, Hyper-V, KVM, QEMU,
 * Xen, VirtualBox, etc.). Ex.: tipo "VMware", fabricante "VMware, Inc.",
 * modelo "VMware7,1".
 */
class Coverage
{
    /** Assinaturas de VM aplicadas a tipo/modelo/fabricante do computador. */
    private const VM_PATTERN = '/vmware|virtualbox|innotek|\bkvm\b|qemu|\bxen\b|hyper-?v|parallels|nutanix|proxmox|bochs|ovirt|rhev|\bvirtual\b/i';

    /** Distribuicoes/familias Linux reconhecidas no nome do SO. */
    private const LINUX_PATTERN = '/linux|ubuntu|debian|centos|red\s?hat|rhel|rocky|alma|suse|sles|fedora|oracle\s+linux|gentoo|\bmint\b|amazon\s+linux|arch|opensuse|manjaro|raspbian|alpine/i';

    /**
     * Decide se um computador e uma VM a partir dos seus rotulos de hardware.
     */
    public static function isVm(?string ...$signals): bool
    {
        foreach ($signals as $signal) {
            $signal = trim((string) $signal);
            if ($signal !== '' && preg_match(self::VM_PATTERN, $signal) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Classifica o SO em 'winserver', 'linux' ou null (fora do escopo).
     */
    public static function osCategory(?string $osName): ?string
    {
        $name = mb_strtolower(trim((string) $osName));

        if ($name === '') {
            return null;
        }

        if (str_contains($name, 'windows') && str_contains($name, 'server')) {
            return 'winserver';
        }

        if (preg_match(self::LINUX_PATTERN, $name) === 1) {
            return 'linux';
        }

        return null;
    }

    /**
     * Lista todas as VMs Linux/Windows Server do GLPI marcando se ja possuem
     * host casado no Nessus (covered) ou nao.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function candidates(): array
    {
        global $DB;

        $covered = self::coveredComputerIds();
        $osByComputer = self::osByComputer();

        $entities = $_SESSION['glpiactiveentities'] ?? null;
        $where = [
            'glpi_computers.is_deleted'  => 0,
            'glpi_computers.is_template' => 0,
        ];
        if (is_array($entities) && $entities !== []) {
            $where['glpi_computers.entities_id'] = $entities;
        }

        $rows = [];
        $iterator = $DB->request([
            'SELECT'    => [
                'glpi_computers.id AS id',
                'glpi_computers.name AS name',
                'glpi_computers.serial AS serial',
                'glpi_computers.entities_id AS entities_id',
                'glpi_computertypes.name AS ctype',
                'glpi_computermodels.name AS cmodel',
                'glpi_manufacturers.name AS manufacturer',
            ],
            'FROM'      => 'glpi_computers',
            'LEFT JOIN' => [
                'glpi_computertypes'  => ['ON' => ['glpi_computertypes' => 'id', 'glpi_computers' => 'computertypes_id']],
                'glpi_computermodels' => ['ON' => ['glpi_computermodels' => 'id', 'glpi_computers' => 'computermodels_id']],
                'glpi_manufacturers'  => ['ON' => ['glpi_manufacturers' => 'id', 'glpi_computers' => 'manufacturers_id']],
            ],
            'WHERE'     => $where,
            'ORDER'     => ['glpi_computers.name ASC'],
        ]);

        foreach ($iterator as $row) {
            $id = (int) $row['id'];

            if (!self::isVm($row['ctype'] ?? null, $row['cmodel'] ?? null, $row['manufacturer'] ?? null)) {
                continue;
            }

            $osName = $osByComputer[$id] ?? '';
            $category = self::osCategory($osName);
            if ($category === null) {
                continue;
            }

            $rows[] = [
                'id'           => $id,
                'name'         => (string) ($row['name'] ?? ''),
                'serial'       => (string) ($row['serial'] ?? ''),
                'entities_id'  => (int) ($row['entities_id'] ?? 0),
                'ctype'        => (string) ($row['ctype'] ?? ''),
                'cmodel'       => (string) ($row['cmodel'] ?? ''),
                'manufacturer' => (string) ($row['manufacturer'] ?? ''),
                'os_name'      => $osName,
                'category'     => $category,
                'covered'      => isset($covered[$id]),
            ];
        }

        return $rows;
    }

    /**
     * Apenas as VMs Linux/Windows Server SEM host Nessus casado.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function uncovered(): array
    {
        return array_values(array_filter(
            self::candidates(),
            static fn (array $row): bool => $row['covered'] === false
        ));
    }

    /**
     * @return array<string, int>
     */
    public static function stats(): array
    {
        $all = self::candidates();

        $stats = [
            'vms_total'         => count($all),
            'covered'           => 0,
            'uncovered'         => 0,
            'uncovered_linux'   => 0,
            'uncovered_winserver' => 0,
        ];

        foreach ($all as $row) {
            if ($row['covered']) {
                $stats['covered']++;
                continue;
            }

            $stats['uncovered']++;
            if ($row['category'] === 'linux') {
                $stats['uncovered_linux']++;
            } elseif ($row['category'] === 'winserver') {
                $stats['uncovered_winserver']++;
            }
        }

        return $stats;
    }

    /**
     * IDs de computadores que ja possuem host casado no Nessus.
     *
     * @return array<int, true>
     */
    private static function coveredComputerIds(): array
    {
        global $DB;

        $covered = [];

        if (!$DB->tableExists(Host::getTable())) {
            return $covered;
        }

        $iterator = $DB->request([
            'SELECT'   => ['items_id'],
            'DISTINCT' => true,
            'FROM'     => Host::getTable(),
            'WHERE'    => [
                'itemtype' => 'Computer',
                'items_id' => ['>', 0],
            ],
        ]);

        foreach ($iterator as $row) {
            $covered[(int) $row['items_id']] = true;
        }

        return $covered;
    }

    /**
     * Mapa computers_id => nome do sistema operacional.
     *
     * @return array<int, string>
     */
    private static function osByComputer(): array
    {
        global $DB;

        $map = [];

        if (!$DB->tableExists('glpi_items_operatingsystems') || !$DB->tableExists('glpi_operatingsystems')) {
            return $map;
        }

        $iterator = $DB->request([
            'SELECT'     => [
                'glpi_items_operatingsystems.items_id AS items_id',
                'glpi_operatingsystems.name AS os_name',
            ],
            'FROM'       => 'glpi_items_operatingsystems',
            'INNER JOIN' => [
                'glpi_operatingsystems' => [
                    'ON' => [
                        'glpi_operatingsystems'        => 'id',
                        'glpi_items_operatingsystems'  => 'operatingsystems_id',
                    ],
                ],
            ],
            'WHERE'      => ['glpi_items_operatingsystems.itemtype' => 'Computer'],
        ]);

        foreach ($iterator as $row) {
            $map[(int) $row['items_id']] = (string) ($row['os_name'] ?? '');
        }

        return $map;
    }
}
