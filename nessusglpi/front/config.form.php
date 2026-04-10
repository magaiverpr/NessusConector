<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Config;
use GlpiPlugin\Nessusglpi\NessusClient;

include('../../../inc/includes.php');

Session::checkRight(Config::$rightname, READ);

$config = Config::getSingleton();
$testResult = null;

if (isset($_POST['update'])) {
    if ((int) ($config->fields['id'] ?? 0) > 0) {
        $config->update($_POST);
    } else {
        $config->add($_POST);
    }

    Html::back();
}

if (isset($_POST['test_connection'])) {
    $candidate = Config::createFromInput($_POST);
    $config = $candidate;

    try {
        $result = (new NessusClient($candidate))->testConnection();
        $testResult = [
            'ok'      => true,
            'message' => (string) ($result['message'] ?? __('Connection successful.', 'nessusglpi')),
        ];
    } catch (Throwable $e) {
        $message = trim((string) $e->getMessage());
        $testResult = [
            'ok'      => false,
            'message' => $message !== ''
                ? $message
                : __('Unexpected error while testing the Nessus connection.', 'nessusglpi'),
        ];
    }
}

Html::header(__('Nessus configuration', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');
$config->showForm((int) ($config->fields['id'] ?? 0), ['test_result' => $testResult]);
Html::footer();
