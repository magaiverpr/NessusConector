(function () {
    'use strict';

    const root = document.querySelector('[data-nessus-list-page]');
    if (!root) {
        return;
    }

    const list = root.querySelector('[data-nessus-list]');
    const rows = list ? Array.from(list.querySelectorAll('[data-nessus-row]')) : [];
    const searchInput = root.querySelector('[data-nessus-list-search]');
    const filter = root.querySelector('[data-nessus-list-filter]');
    const counter = root.querySelector('[data-nessus-list-count]');
    const totalCounter = root.querySelector('[data-nessus-list-total]');
    const clearButton = root.querySelector('[data-nessus-list-clear]');
    const emptyState = root.querySelector('[data-nessus-list-empty]');
    const selectionBar = root.querySelector('[data-nessus-selection-bar]');
    const selectionCount = root.querySelector('[data-nessus-selection-count]');
    const masterCheckbox = root.querySelector('[data-nessus-master-check]');
    const bulkDeleteBtn = root.querySelector('[data-nessus-bulk-delete]');
    const bulkForm = document.getElementById(root.dataset.nessusBulkForm || '');

    const toastHost = ensureToastHost();
    let activeModal = null;

    function normalize(value) {
        return (value || '').toString().toLowerCase().trim();
    }

    function visibleRows() {
        return rows.filter((row) => !row.hidden);
    }

    function checkedRows() {
        return rows.filter((row) => {
            const cb = row.querySelector('[data-nessus-row-check]');
            return cb && cb.checked && !row.hidden;
        });
    }

    function updateSelectionBar() {
        const selected = checkedRows();
        if (!selectionBar) {
            return;
        }
        if (selected.length > 0) {
            selectionBar.classList.add('is-active');
            if (selectionCount) {
                selectionCount.textContent = selected.length.toString();
            }
        } else {
            selectionBar.classList.remove('is-active');
        }

        if (masterCheckbox) {
            const visible = visibleRows();
            if (selected.length === 0) {
                masterCheckbox.checked = false;
                masterCheckbox.indeterminate = false;
            } else if (selected.length === visible.length && visible.length > 0) {
                masterCheckbox.checked = true;
                masterCheckbox.indeterminate = false;
            } else {
                masterCheckbox.checked = false;
                masterCheckbox.indeterminate = true;
            }
        }

        for (const row of rows) {
            const cb = row.querySelector('[data-nessus-row-check]');
            row.dataset.selected = cb && cb.checked ? 'true' : 'false';
        }
    }

    function applyFilter() {
        const query = normalize(searchInput ? searchInput.value : '');
        const status = filter ? filter.value : 'all';
        let visible = 0;

        for (const row of rows) {
            const haystack = row.dataset.haystack || '';
            const rowStatus = row.dataset.status || '';
            const matchesQuery = query === '' || haystack.indexOf(query) !== -1;
            const matchesStatus = status === 'all' || rowStatus === status;
            const show = matchesQuery && matchesStatus;
            row.hidden = !show;
            if (show) {
                visible++;
            }
        }

        if (counter) counter.textContent = visible.toString();
        if (totalCounter) totalCounter.textContent = rows.length.toString();

        if (emptyState) {
            emptyState.hidden = visible !== 0 || rows.length === 0;
        }

        if (clearButton) {
            clearButton.hidden = !(query !== '' || status !== 'all');
        }

        updateSelectionBar();
    }

    if (searchInput) {
        let debounce;
        searchInput.addEventListener('input', () => {
            window.clearTimeout(debounce);
            debounce = window.setTimeout(applyFilter, 80);
        });
        searchInput.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && searchInput.value !== '') {
                event.preventDefault();
                searchInput.value = '';
                applyFilter();
            }
        });
    }

    if (filter) {
        filter.addEventListener('change', applyFilter);
    }

    if (clearButton) {
        clearButton.addEventListener('click', (event) => {
            event.preventDefault();
            if (searchInput) searchInput.value = '';
            if (filter) filter.value = 'all';
            applyFilter();
        });
    }

    if (masterCheckbox) {
        masterCheckbox.addEventListener('change', () => {
            const target = masterCheckbox.checked;
            for (const row of visibleRows()) {
                const cb = row.querySelector('[data-nessus-row-check]');
                if (cb) {
                    cb.checked = target;
                }
            }
            updateSelectionBar();
        });
    }

    list && list.addEventListener('change', (event) => {
        if (event.target.matches('[data-nessus-row-check]')) {
            updateSelectionBar();
        }
    });

    // Copy on click for scan ID / numeric ID
    root.addEventListener('click', (event) => {
        const target = event.target.closest('[data-nessus-copy]');
        if (!target) {
            return;
        }
        const value = target.getAttribute('data-nessus-copy');
        if (!value) {
            return;
        }
        event.preventDefault();
        copyText(value);
        target.classList.add('is-copied');
        const previousTitle = target.getAttribute('title');
        target.setAttribute('title', 'Copied!');
        window.setTimeout(() => {
            target.classList.remove('is-copied');
            if (previousTitle !== null) {
                target.setAttribute('title', previousTitle);
            } else {
                target.removeAttribute('title');
            }
        }, 1100);
    });

    function copyText(value) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).catch(() => fallbackCopy(value));
        } else {
            fallbackCopy(value);
        }
    }

    function fallbackCopy(value) {
        const helper = document.createElement('textarea');
        helper.value = value;
        helper.setAttribute('readonly', '');
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        helper.style.left = '-9999px';
        document.body.appendChild(helper);
        helper.select();
        try {
            document.execCommand('copy');
        } catch (_error) {
            // best effort
        }
        document.body.removeChild(helper);
    }

    // Bulk delete confirmation
    if (bulkDeleteBtn && bulkForm) {
        bulkDeleteBtn.addEventListener('click', (event) => {
            event.preventDefault();
            const selected = checkedRows();
            if (selected.length === 0) {
                showToast({
                    type: 'warning',
                    message: bulkDeleteBtn.dataset.emptyText || 'Select at least one scan to delete.',
                });
                return;
            }

            confirmModal({
                variant: 'danger',
                title: bulkDeleteBtn.dataset.confirmTitle || 'Delete selected scans?',
                message: (bulkDeleteBtn.dataset.confirmMessage || 'This will permanently remove %d scan(s) and all related plugin data.').replace('%d', selected.length.toString()),
                confirmLabel: bulkDeleteBtn.dataset.confirmLabel || 'Delete',
                cancelLabel: bulkDeleteBtn.dataset.cancelLabel || 'Cancel',
            }).then((confirmed) => {
                if (!confirmed) return;
                const trigger = document.createElement('input');
                trigger.type = 'hidden';
                trigger.name = bulkDeleteBtn.dataset.bulkAction || 'delete_selected_scans';
                trigger.value = '1';
                bulkForm.appendChild(trigger);
                bulkForm.submit();
            });
        });
    }

    // Per-row sync: confirmation modal + AJAX submit so the user gets instant feedback
    // (row pulses as syncing, queue badge ticks up, no full-page navigation).
    root.addEventListener('submit', (event) => {
        const form = event.target.closest('[data-nessus-sync-form]');
        if (!form) {
            return;
        }
        event.preventDefault();

        confirmModal({
            variant: 'info',
            title: form.dataset.confirmTitle || 'Queue scan synchronization?',
            message: form.dataset.confirmMessage || 'The plugin will queue a synchronization job for this scan.',
            confirmLabel: form.dataset.confirmLabel || 'Queue',
            cancelLabel: form.dataset.cancelLabel || 'Cancel',
        }).then((confirmed) => {
            if (!confirmed) return;
            submitRowSync(form);
        });
    });

    function submitRowSync(form) {
        const row = form.closest('[data-nessus-row]');
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
        }
        if (row && root._nessusSyncMarkRow) {
            root._nessusSyncMarkRow(row);
        }

        const payload = new FormData(form);
        payload.set('sync_scan', '1');

        fetch(form.action || 'scan.sync.php', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
            },
            body: payload,
        })
            .then(async (response) => {
                let data = null;
                try {
                    data = await response.json();
                } catch (_e) {
                    data = null;
                }

                if (!data || !data.ok) {
                    if (row && root._nessusSyncClearRow) {
                        root._nessusSyncClearRow(row);
                    }
                    showToast({
                        type: 'error',
                        message: (data && data.message) ? data.message : 'Could not queue this scan.',
                        ttl: 4200,
                    });
                    return;
                }

                showToast({
                    type: 'info',
                    message: data.message || 'Synchronization queued.',
                    ttl: 2400,
                });

                if (root._nessusSyncBumpQueue) {
                    root._nessusSyncBumpQueue();
                }
                if (root._nessusSyncKick) {
                    root._nessusSyncKick();
                }
            })
            .catch(() => {
                if (row && root._nessusSyncClearRow) {
                    root._nessusSyncClearRow(row);
                }
                showToast({
                    type: 'error',
                    message: 'Could not contact the server. Try again in a moment.',
                    ttl: 4200,
                });
            })
            .finally(() => {
                if (submitBtn) {
                    submitBtn.disabled = false;
                }
            });
    }

    // ----- Modal -----
    function confirmModal(opts) {
        return new Promise((resolve) => {
            if (activeModal) {
                activeModal.dismiss();
            }

            const backdrop = document.createElement('div');
            backdrop.className = 'nessus-modal-backdrop';

            const variant = opts.variant === 'danger' ? 'danger' : 'info';
            const modal = document.createElement('div');
            modal.className = 'nessus-modal nessus-modal--' + variant;
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');

            const iconSvg = variant === 'danger'
                ? svgIcon('<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/>')
                : svgIcon('<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>');

            const confirmBtnClass = variant === 'danger' ? 'nessus-btn-danger' : 'nessus-btn-primary';

            modal.innerHTML =
                '<div class="nessus-modal__header">' +
                '  <div class="nessus-modal__icon">' + iconSvg + '</div>' +
                '  <h3 class="nessus-modal__title"></h3>' +
                '</div>' +
                '<div class="nessus-modal__body"></div>' +
                '<div class="nessus-modal__footer">' +
                '  <button type="button" class="nessus-btn-outline" data-action="cancel"></button>' +
                '  <button type="button" class="' + confirmBtnClass + '" data-action="confirm"></button>' +
                '</div>';

            modal.querySelector('.nessus-modal__title').textContent = opts.title || '';
            modal.querySelector('.nessus-modal__body').textContent = opts.message || '';
            const cancelBtn = modal.querySelector('[data-action="cancel"]');
            const confirmBtn = modal.querySelector('[data-action="confirm"]');
            cancelBtn.textContent = opts.cancelLabel || 'Cancel';
            confirmBtn.textContent = opts.confirmLabel || 'Confirm';

            document.body.appendChild(backdrop);
            document.body.appendChild(modal);

            function dismiss(result) {
                modal.classList.remove('is-visible');
                backdrop.classList.remove('is-visible');
                window.setTimeout(() => {
                    modal.remove();
                    backdrop.remove();
                }, 200);
                document.removeEventListener('keydown', onKey);
                activeModal = null;
                resolve(result);
            }

            function onKey(event) {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    dismiss(false);
                }
                if (event.key === 'Enter') {
                    event.preventDefault();
                    dismiss(true);
                }
            }

            activeModal = { dismiss: () => dismiss(false) };

            backdrop.addEventListener('click', () => dismiss(false));
            cancelBtn.addEventListener('click', () => dismiss(false));
            confirmBtn.addEventListener('click', () => dismiss(true));
            document.addEventListener('keydown', onKey);

            window.requestAnimationFrame(() => {
                backdrop.classList.add('is-visible');
                modal.classList.add('is-visible');
                confirmBtn.focus();
            });
        });
    }

    // ----- Toast -----
    function ensureToastHost() {
        let host = document.querySelector('.nessus-toast-host');
        if (!host) {
            host = document.createElement('div');
            host.className = 'nessus-toast-host';
            document.body.appendChild(host);
        }
        return host;
    }

    function showToast(opts) {
        const type = opts.type || 'info';
        const toast = document.createElement('div');
        toast.className = 'nessus-toast nessus-toast--' + type;

        const iconPath = {
            success: '<path d="M20 6 9 17l-5-5"/>',
            warning: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/>',
            error: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
            info: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
        }[type] || '<circle cx="12" cy="12" r="10"/>';

        toast.innerHTML =
            '<span class="nessus-toast__icon">' + svgIcon(iconPath) + '</span>' +
            '<div class="nessus-toast__body"></div>' +
            '<button type="button" class="nessus-toast__close" aria-label="Close">&times;</button>';

        toast.querySelector('.nessus-toast__body').textContent = opts.message || '';
        toast.querySelector('.nessus-toast__close').addEventListener('click', () => removeToast(toast));

        toastHost.appendChild(toast);
        window.requestAnimationFrame(() => toast.classList.add('is-visible'));

        const ttl = typeof opts.ttl === 'number' ? opts.ttl : 4200;
        if (ttl > 0) {
            window.setTimeout(() => removeToast(toast), ttl);
        }
    }

    function removeToast(toast) {
        toast.classList.remove('is-visible');
        window.setTimeout(() => toast.remove(), 280);
    }

    function svgIcon(inner) {
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + '</svg>';
    }

    // ----- Sync queue monitor (status polling only; cron does the heavy work) -----
    const queueConfig = root.dataset.nessusQueue ? safeJsonParse(root.dataset.nessusQueue) : null;
    if (queueConfig && queueConfig.url) {
        startSyncQueueWorker(queueConfig);
    }

    function startSyncQueueWorker(config) {
        const i18n = config.i18n || {};
        const queuePill = root.querySelector('[data-nessus-queue-pill]');
        const queuePillLabel = queuePill ? queuePill.querySelector('[data-nessus-queue-pill-label]') : null;
        let pendingTimer = null;
        let consecutiveErrors = 0;
        let lastCheckedAt = config.checkedAt || '';

        const STATUS_BUCKETS = ['success', 'running', 'warning', 'danger', 'muted', 'unknown'];

        function setQueuePill(count, variant) {
            if (!queuePill || !queuePillLabel) {
                return;
            }
            const safeCount = Math.max(0, count | 0);
            if (safeCount <= 0) {
                queuePill.hidden = true;
                queuePillLabel.textContent = '';
                return;
            }
            queuePill.hidden = false;
            queuePill.classList.remove('nessus-stat-pill--warn', 'nessus-stat-pill--muted');
            queuePill.classList.add('nessus-stat-pill--' + (variant === 'muted' ? 'muted' : 'warn'));
            const tpl = (variant === 'muted')
                ? (safeCount === 1 ? (i18n.queueWaitSingular || '%d job waiting') : (i18n.queueWaitPlural || '%d jobs waiting'))
                : (safeCount === 1 ? (i18n.queueOpenSingular || '%d job in queue') : (i18n.queueOpenPlural || '%d jobs in queue'));
            queuePillLabel.textContent = tpl.replace('%d', String(safeCount));
            queuePill.setAttribute('data-nessus-queue-count', String(safeCount));
        }

        function findRow(scanInternalId) {
            if (!list || !scanInternalId) {
                return null;
            }
            return list.querySelector('[data-nessus-row][data-nessus-scan-id="' + (scanInternalId | 0) + '"]');
        }

        function markRowSyncing(row) {
            if (!row) {
                return;
            }
            row.setAttribute('data-nessus-syncing', 'true');
            const status = row.querySelector('.nessus-status');
            if (status) {
                if (!status.hasAttribute('data-nessus-original-label')) {
                    status.setAttribute('data-nessus-original-label', status.textContent.trim());
                }
                status.textContent = i18n.rowSyncing || 'Syncing…';
                STATUS_BUCKETS.forEach((b) => status.classList.remove('nessus-status--' + b));
                status.classList.add('nessus-status--running');
            }
        }

        function clearRowSyncing(row) {
            if (!row) {
                return;
            }
            row.removeAttribute('data-nessus-syncing');
            const status = row.querySelector('.nessus-status');
            if (status && status.hasAttribute('data-nessus-original-label')) {
                status.removeAttribute('data-nessus-original-label');
            }
        }

        function applyJobUpdateToRow(row, job) {
            if (!row || !job) {
                return;
            }

            clearRowSyncing(row);

            const bucket = String(job.last_sync_bucket || 'unknown');
            row.setAttribute('data-status', bucket);

            const status = row.querySelector('.nessus-status');
            if (status) {
                STATUS_BUCKETS.forEach((b) => status.classList.remove('nessus-status--' + b));
                status.classList.add('nessus-status--' + bucket);
                status.textContent = String(job.last_sync_label || '');
                if (job.last_sync_status) {
                    status.setAttribute('title', String(job.last_sync_status));
                }
            }

            // Visually pulse the row briefly so the user sees what changed.
            row.classList.add('is-just-synced');
            window.setTimeout(() => row.classList.remove('is-just-synced'), 1600);

            // Refresh the haystack so client-side search keeps matching after the status change.
            const haystackParts = [
                row.dataset.haystack || '',
                String(job.last_sync_status || ''),
                bucket,
            ];
            row.dataset.haystack = haystackParts.join(' ').toLowerCase();
        }

        function reportJob(job) {
            if (!job) {
                return;
            }

            const row = findRow(job.scan_internal_id);
            applyJobUpdateToRow(row, job);

            const status = String(job.status || '').toLowerCase();
            const scanName = job.scan_name || '#' + (job.scan_internal_id || '?');

            if (status === 'success') {
                showToast({
                    type: 'success',
                    message: (i18n.jobSuccess || 'Synchronization of "%s" finished.').replace('%s', scanName),
                    ttl: 3000,
                });
            } else if (status === 'error') {
                const baseMsg = (i18n.jobError || 'Synchronization of "%s" failed.').replace('%s', scanName);
                const full = job.message ? baseMsg + ' — ' + job.message : baseMsg;
                showToast({
                    type: 'error',
                    message: full,
                    ttl: 5200,
                });
            }
        }

        function scheduleNext(delayMs) {
            if (pendingTimer !== null) {
                window.clearTimeout(pendingTimer);
            }
            pendingTimer = window.setTimeout(tick, Math.max(0, delayMs));
        }

        async function tick() {
            pendingTimer = null;

            if (document.hidden) {
                // Avoid burning cycles when the tab is in the background. Resume on focus.
                scheduleNext(config.idlePollMs || 15000);
                return;
            }

            // Read-only status poll => GET, so it does not consume the page's
            // one-time CSRF token (which is shared by the sync action forms).
            const params = new URLSearchParams();
            if (lastCheckedAt) {
                params.set('since', lastCheckedAt);
            }
            const query = params.toString();
            const requestUrl = query ? `${config.url}?${query}` : config.url;

            try {
                const response = await fetch(requestUrl, {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                });

                let data = null;
                try {
                    data = await response.json();
                } catch (_e) {
                    data = null;
                }

                consecutiveErrors = 0;

                if (data && typeof data === 'object') {
                    const jobs = Array.isArray(data.jobs) ? data.jobs : (data.job ? [data.job] : []);
                    for (const job of jobs) {
                        reportJob(job);
                    }
                    if (data.checked_at) {
                        lastCheckedAt = String(data.checked_at);
                    }

                    const remaining = Math.max(0, parseInt(data.remaining, 10) || 0);
                    const open      = Math.max(0, parseInt(data.open, 10) || 0);

                    if (open > 0) {
                        setQueuePill(open, 'warn');
                    } else if (remaining > 0) {
                        setQueuePill(remaining, 'muted');
                    } else {
                        setQueuePill(0, 'warn');
                    }

                    scheduleNext(open > 0 || remaining > 0 ? 5000 : (config.idlePollMs || 15000));
                } else {
                    throw new Error('Bad payload');
                }
            } catch (_error) {
                consecutiveErrors++;
                const backoff = Math.min(60000, 2000 * Math.pow(2, Math.min(5, consecutiveErrors)));
                showToast({
                    type: 'error',
                    message: i18n.errorMessage || 'Could not contact the sync queue status endpoint. Will retry shortly.',
                    ttl: 2600,
                });
                scheduleNext(backoff);
            }
        }

        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && pendingTimer === null) {
                scheduleNext(120);
            }
        });

        // Hooks exposed for the per-row sync submit handler so it can react instantly
        // (mark row, bump queue badge, kick the polling loop) before the worker observes it.
        root._nessusSyncMarkRow  = markRowSyncing;
        root._nessusSyncClearRow = clearRowSyncing;
        root._nessusSyncBumpQueue = () => {
            const current = parseInt(queuePill?.getAttribute('data-nessus-queue-count') || '0', 10) || 0;
            setQueuePill(current + 1, 'warn');
        };
        root._nessusSyncKick = () => {
            scheduleNext(1000);
        };

        const openJobs = parseInt(config.openJobs, 10) || 0;
        if (openJobs > 0) {
            showToast({
                type: 'info',
                message: (i18n.startMessage || 'Monitoring %d queued synchronization job(s)…').replace('%d', String(openJobs)),
                ttl: 2400,
            });
            setQueuePill(openJobs, 'warn');
            scheduleNext(1000);
        } else {
            // Poll idly so another tab or cron completion is reflected without reloading.
            scheduleNext(config.idlePollMs || 15000);
        }
    }

    function safeJsonParse(value) {
        try {
            return JSON.parse(value);
        } catch (_error) {
            return null;
        }
    }

    applyFilter();
})();
