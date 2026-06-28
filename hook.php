<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Profile;
use GlpiPlugin\Nessusglpi\SyncCron;

function plugin_nessusglpi_install(): bool
{
    require_once __DIR__ . '/sql/install.php';

    if (!plugin_nessusglpi_run_install()) {
        return false;
    }

    Profile::ensureProfileRights();
    plugin_nessusglpi_register_crontasks();

    return true;
}

function plugin_nessusglpi_register_crontasks(): void
{
    global $DB;

    // Drains the sync queue unattended so synchronization never depends on an open browser tab.
    // This task can run for a long time, so production must execute it through external cron/CLI.
    CronTask::register(SyncCron::class, 'queue', 5 * MINUTE_TIMESTAMP, [
        'comment'   => __('Process queued Nessus synchronization jobs', 'nessusglpi'),
        'mode'      => CronTask::MODE_EXTERNAL,
        'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
        'state'     => CronTask::STATE_WAITING,
    ]);

    $DB->update('glpi_crontasks', [
        'mode' => CronTask::MODE_EXTERNAL,
    ], [
        'itemtype' => SyncCron::class,
        'name'     => 'queue',
    ]);

    // Periodically re-queues active scans that have not synced within the task frequency.
    CronTask::register(SyncCron::class, 'autosync', DAY_TIMESTAMP, [
        'comment'   => __('Queue active Nessus scans for periodic synchronization', 'nessusglpi'),
        'mode'      => CronTask::MODE_INTERNAL,
        'allowmode' => CronTask::MODE_INTERNAL | CronTask::MODE_EXTERNAL,
        'state'     => CronTask::STATE_WAITING,
    ]);
}

function plugin_nessusglpi_uninstall(): bool
{
    global $DB;

    require_once __DIR__ . '/sql/uninstall.php';

    // The crontasks use a namespaced itemtype, so CronTask::unregister() (which matches the
    // legacy "Plugin<name>" convention) would not catch them — delete them by itemtype.
    $DB->delete('glpi_crontasks', ['itemtype' => SyncCron::class]);

    plugin_nessusglpi_run_uninstall();

    $rights = array_column(Profile::getAllRights(), 'field');
    if (!empty($rights)) {
        ProfileRight::deleteProfileRights($rights);
    }

    return true;
}
