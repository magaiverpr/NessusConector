<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use RuntimeException;
use Session;
use Throwable;

class SyncJobService
{
    public function queueScan(int $scanId): int
    {
        global $DB;

        $scan = new Scan();
        if (!$scan->getFromDB($scanId)) {
            throw new RuntimeException(__('Scan not found.', 'nessusglpi'));
        }

        $existing = $DB->request([
            'FROM'  => SyncJob::getTable(),
            'WHERE' => [
                'plugin_nessusglpi_scans_id' => $scanId,
                'status'                     => ['pending', 'running'],
            ],
            'ORDER' => ['id DESC'],
            'LIMIT' => 1,
        ])->current();

        if ($existing) {
            return (int) $existing['id'];
        }

        $now = date('Y-m-d H:i:s');
        $job = new SyncJob();
        $jobId = $job->add([
            'plugin_nessusglpi_scans_id' => $scanId,
            'entities_id'                => (int) ($scan->fields['entities_id'] ?? 0),
            'status'                     => 'pending',
            'requested_by'               => (int) (method_exists(Session::class, 'getLoginUserID') ? Session::getLoginUserID() : 0),
            'requested_at'               => $now,
            'date_creation'              => $now,
        ]);

        if (!$jobId) {
            throw new RuntimeException(__('Unable to queue the synchronization job.', 'nessusglpi'));
        }

        $scan->update([
            'id'               => $scanId,
            'last_sync_status' => 'queued',
        ]);

        return (int) $jobId;
    }

    public function countPendingJobs(array $entityIds = []): int
    {
        return $this->countJobsByStatus(['pending'], $entityIds);
    }

    public function countOpenJobs(array $entityIds = []): int
    {
        return $this->countJobsByStatus(['pending', 'running'], $entityIds);
    }

    public function getRecentlyFinishedJobs(array $entityIds = [], string $finishedSince = '', int $limit = 20): array
    {
        global $DB;

        $criteria = [
            'status' => ['success', 'error'],
        ];
        if ($entityIds !== []) {
            $criteria['entities_id'] = $entityIds;
        }

        $finishedSince = trim($finishedSince);
        if ($finishedSince !== '') {
            $timestamp = strtotime($finishedSince);
            if ($timestamp !== false) {
                $criteria['finished_at'] = ['>', date('Y-m-d H:i:s', $timestamp)];
            }
        }

        $jobs = [];
        $iterator = $DB->request([
            'FROM'  => SyncJob::getTable(),
            'WHERE' => $criteria,
            'ORDER' => ['finished_at DESC', 'id DESC'],
            'LIMIT' => max(1, min(50, $limit)),
        ]);

        foreach ($iterator as $row) {
            $jobs[] = $row;
        }

        return array_reverse($jobs);
    }

    public function processNextPendingJob(array $entityIds = []): ?array
    {
        global $DB;

        $criteria = [
            'status' => 'pending',
        ];
        if ($entityIds !== []) {
            $criteria['entities_id'] = $entityIds;
        }

        $jobRow = $DB->request([
            'FROM'  => SyncJob::getTable(),
            'WHERE' => $criteria,
            'ORDER' => ['id ASC'],
            'LIMIT' => 1,
        ])->current();

        if (!$jobRow) {
            return null;
        }

        $jobId = (int) ($jobRow['id'] ?? 0);
        $scanId = (int) ($jobRow['plugin_nessusglpi_scans_id'] ?? 0);
        $now = date('Y-m-d H:i:s');

        $job = new SyncJob();
        if (!$job->getFromDB($jobId)) {
            return null;
        }

        $job->update([
            'id'         => $jobId,
            'status'     => 'running',
            'started_at' => $now,
        ]);

        try {
            $runId = (new SyncService())->runScan($scanId);
            $finishedAt = date('Y-m-d H:i:s');
            $job->update([
                'id'          => $jobId,
                'status'      => 'success',
                'finished_at' => $finishedAt,
                'run_id'      => $runId,
                'message'     => sprintf(__('Synchronization completed. Run #%d created.', 'nessusglpi'), $runId),
            ]);

            AuditLog::info('sync', sprintf('Scan #%d synchronized (run #%d).', $scanId, $runId), [
                'job_id'  => $jobId,
                'scan_id' => $scanId,
                'run_id'  => $runId,
            ]);

            return [
                'job_id'     => $jobId,
                'scan_id'    => $scanId,
                'run_id'     => $runId,
                'status'     => 'success',
                'remaining'  => $this->countPendingJobs($entityIds),
            ];
        } catch (Throwable $e) {
            $finishedAt = date('Y-m-d H:i:s');
            $job->update([
                'id'          => $jobId,
                'status'      => 'error',
                'finished_at' => $finishedAt,
                'message'     => $e->getMessage(),
            ]);

            AuditLog::error('sync', sprintf('Scan #%d synchronization failed: %s', $scanId, $e->getMessage()), [
                'job_id'  => $jobId,
                'scan_id' => $scanId,
            ]);

            return [
                'job_id'    => $jobId,
                'scan_id'   => $scanId,
                'status'    => 'error',
                'message'   => $e->getMessage(),
                'remaining' => $this->countPendingJobs($entityIds),
            ];
        }
    }

    private function countJobsByStatus(array $statuses, array $entityIds = []): int
    {
        global $DB;

        $criteria = [
            'status' => count($statuses) === 1 ? $statuses[0] : $statuses,
        ];

        if ($entityIds !== []) {
            $criteria['entities_id'] = $entityIds;
        }

        $count = 0;
        $iterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => SyncJob::getTable(),
            'WHERE'  => $criteria,
        ]);

        foreach ($iterator as $_row) {
            $count++;
        }

        return $count;
    }
}
