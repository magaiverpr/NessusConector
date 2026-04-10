<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Profile;

function plugin_nessusglpi_install(): bool
{
    require_once __DIR__ . '/sql/install.php';

    if (!plugin_nessusglpi_run_install()) {
        return false;
    }

    Profile::ensureProfileRights();

    return true;
}

function plugin_nessusglpi_uninstall(): bool
{
    require_once __DIR__ . '/sql/uninstall.php';

    plugin_nessusglpi_run_uninstall();

    $rights = array_column(Profile::getAllRights(), 'field');
    if (!empty($rights)) {
        ProfileRight::deleteProfileRights($rights);
    }

    return true;
}
