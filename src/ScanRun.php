<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;
use CommonGLPI;

class ScanRun extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_scan_runs';

    public static $rightname = 'plugin_nessusglpi_scan';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_scan_runs';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Nessus scan run', 'nessusglpi');
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string
    {
        if ($item instanceof Scan) {
            return __('History', 'nessusglpi');
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
    {
        if ($item instanceof Scan) {
            echo "<div class='card card-body'>";
            echo '<h3>' . __('Scan history', 'nessusglpi') . '</h3>';
            echo '<p>' . __('Open the dedicated history page to inspect synchronization runs.', 'nessusglpi') . '</p>';
            echo '</div>';
        }

        return true;
    }
}
