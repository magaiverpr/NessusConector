<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;
use Session;

class Host extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_hosts';

    public static $rightname = 'plugin_nessusglpi_vulnerability';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_hosts';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Imported host', 'nessusglpi');
    }

    public static function canDelete(): bool
    {
        return Session::haveRight(static::$rightname, UPDATE) > 0;
    }

    public static function deleteByIds(array $ids): int
    {
        $deleted = 0;

        foreach ($ids as $id) {
            $host = new self();
            if ($host->delete(['id' => (int) $id], true)) {
                $deleted++;
            }
        }

        return $deleted;
    }
}
