<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CronTask;
use Throwable;

class SyncCron
{
    // Each sync job triggers many outbound HTTP calls to Tenable, so a single cron tick
    // only drains a bounded number of jobs and yields; the next tick continues the queue.
    private const MAX_JOBS_PER_RUN = 10;

    public static function cronInfo(string $name): array
    {
        return match ($name) {
            'queue'    => ['description' => __('Process queued Nessus synchronization jobs', 'nessusglpi')],
            'autosync' => ['description' => __('Queue active Nessus scans for periodic synchronization', 'nessusglpi')],
            default    => [],
        };
    }

    /**
     * Drains the pending sync-job queue without requiring an open browser tab.
     *
     * @return int >0 when work was done, 0 when the queue was empty.
     */
    public static function cronQueue(CronTask $task): int
    {
        $service   = new SyncJobService();
        $processed = 0;

        for ($i = 0; $i < self::MAX_JOBS_PER_RUN; $i++) {
            $result = $service->processNextPendingJob([]);
            if ($result === null) {
                break;
            }

            $processed++;
            $task->addVolume(1);

            if (($result['status'] ?? '') === 'error') {
                $task->log(sprintf(
                    'Scan #%d synchronization failed: %s',
                    (int) ($result['scan_id'] ?? 0),
                    (string) ($result['message'] ?? '')
                ));
            }
        }

        return $processed > 0 ? 1 : 0;
    }

    /**
     * Enqueues active scans whose last synchronization is older than this task's frequency,
     * so the queue cron picks them up on its next tick.
     *
     * @return int >0 when at least one scan was queued, 0 otherwise.
     */
    public static function cronAutosync(CronTask $task): int
    {
        global $DB;

        $frequency = (int) ($task->fields['frequency'] ?? 0);
        if ($frequency <= 0) {
            $frequency = DAY_TIMESTAMP;
        }
        $threshold = date('Y-m-d H:i:s', time() - $frequency);

        $service = new SyncJobService();
        $queued  = 0;

        $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Scan::getTable(),
            'WHERE'  => [
                'is_active' => 1,
                'OR'        => [
                    ['last_sync_at' => null],
                    ['last_sync_at' => ['<', $threshold]],
                ],
            ],
        ]);

        foreach ($iterator as $row) {
            $scanId = (int) ($row['id'] ?? 0);
            if ($scanId <= 0) {
                continue;
            }

            try {
                $service->queueScan($scanId);
                $queued++;
                $task->addVolume(1);
            } catch (Throwable $e) {
                $task->log(sprintf('Could not queue scan #%d: %s', $scanId, $e->getMessage()));
            }
        }

        return $queued > 0 ? 1 : 0;
    }
}
