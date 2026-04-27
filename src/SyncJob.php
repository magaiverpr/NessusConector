<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;

class SyncJob extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_sync_jobs';

    public static $rightname = 'plugin_nessusglpi_scan';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_sync_jobs';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Sync job', 'nessusglpi');
    }
}
