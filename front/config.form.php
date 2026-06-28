<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Config;

include('../../../inc/includes.php');

Session::checkRight(Config::$rightname, READ);

$config = Config::getSingleton();

if (isset($_POST['update'])) {
    Session::checkRight(Config::$rightname, UPDATE);

    if ((int) ($config->fields['id'] ?? 0) > 0) {
        $config->update($_POST);
    } else {
        $config->add($_POST);
    }

    Html::back();
}

Html::header(__('Nessus configuration', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');
$config->showForm((int) ($config->fields['id'] ?? 0));
Html::footer();
