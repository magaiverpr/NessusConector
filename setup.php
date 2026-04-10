<?php

declare(strict_types=1);

use Glpi\Plugin\Hooks;
use GlpiPlugin\Nessusglpi\Profile as NessusProfile;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\Vulnerability;

define('PLUGIN_NESSUSGLPI_VERSION', '1.0.0');

function plugin_init_nessusglpi(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS[Hooks::CSRF_COMPLIANT]['nessusglpi'] = true;
    $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['nessusglpi'] = 'front/config.form.php';
    $PLUGIN_HOOKS[Hooks::MENU_TOADD]['nessusglpi'] = [
        'plugins' => Scan::class,
    ];

    Plugin::registerClass(NessusProfile::class, [
        'addtabon' => [\Profile::class],
    ]);

    Plugin::registerClass(Vulnerability::class, [
        'addtabon' => [
            Computer::class,
            NetworkEquipment::class,
            Printer::class,
            Phone::class,
            Unmanaged::class,
        ],
    ]);
}

function plugin_version_nessusglpi(): array
{
    return [
        'name'         => __('Nessus Conector', 'nessusglpi'),
        'version'      => PLUGIN_NESSUSGLPI_VERSION,
        'author'       => 'Codex',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://glpi-project.org',
        'requirements' => [
            'glpi' => [
                'min' => '11.0.0',
                'max' => '11.0.99',
            ],
        ],
    ];
}

function plugin_nessusglpi_check_prerequisites(): bool
{
    if (version_compare(GLPI_VERSION, '11.0.0', '<') || version_compare(GLPI_VERSION, '11.1.0', '>=')) {
        echo __('This plugin requires GLPI 11.0.x.', 'nessusglpi');
        return false;
    }

    return true;
}

function plugin_nessusglpi_check_config(bool $verbose = false): bool
{
    return true;
}
