<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;

class HostTicket extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_host_tickets';

    public static $rightname = 'plugin_nessusglpi_ticket';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_host_tickets';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Host ticket link', 'nessusglpi');
    }
}
