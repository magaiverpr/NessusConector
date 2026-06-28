(function () {
    'use strict';

    const root = document.querySelector('[data-nessus-vuln-page]');
    if (!root) {
        return;
    }

    const searchInput = root.querySelector('[data-nessus-vuln-search]');
    const ticketFilter = root.querySelector('[data-nessus-vuln-ticket-filter]');
    const list = root.querySelector('[data-nessus-vuln-list]');
    const rows = list ? Array.from(list.querySelectorAll('[data-nessus-vuln-row]')) : [];
    const counter = root.querySelector('[data-nessus-vuln-count]');
    const totalCounter = root.querySelector('[data-nessus-vuln-total]');
    const emptyState = root.querySelector('[data-nessus-vuln-empty]');
    const selectionBar = root.querySelector('[data-nessus-vuln-selection-bar]');
    const selectionCount = root.querySelector('[data-nessus-vuln-selection-count]');
    const masterCheckbox = root.querySelector('[data-nessus-vuln-master-check]');
    const bulkForm = document.getElementById(root.dataset.nessusBulkForm || '');
    const sevCards = Array.from(root.querySelectorAll('[data-nessus-sev-card]'));

    const activeSeverities = new Set();
    let activeTicketFilter = 'all';
    const toastHost = ensureToastHost();
    let activeModal = null;

    function normalize(value) {
        return (value || '').toString().toLowerCase().trim();
    }

    function visibleRows() {
        return rows.filter((row) => !row.hidden);
    }

    function visibleSelectableRows() {
        return visibleRows().filter((row) => row.querySelector('[data-nessus-vuln-row-check]'));
    }

    function checkedRows() {
        return rows.filter((row) => {
            const cb = row.querySelector('[data-nessus-vuln-row-check]');
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
            const selectable = visibleSelectableRows();
            if (selectable.length === 0 || selected.length === 0) {
                masterCheckbox.checked = false;
                masterCheckbox.indeterminate = false;
                masterCheckbox.disabled = selectable.length === 0;
            } else if (selected.length === selectable.length) {
                masterCheckbox.checked = true;
                masterCheckbox.indeterminate = false;
                masterCheckbox.disabled = false;
            } else {
                masterCheckbox.checked = false;
                masterCheckbox.indeterminate = true;
                masterCheckbox.disabled = false;
            }
        }

        for (const row of rows) {
            const cb = row.querySelector('[data-nessus-vuln-row-check]');
            row.dataset.selected = cb && cb.checked ? 'true' : 'false';
        }
    }

    function applyFilter() {
        const query = normalize(searchInput ? searchInput.value : '');
        let visible = 0;

        for (const row of rows) {
            const haystack = row.dataset.haystack || '';
            const severity = row.dataset.severity || '';
            const hasTicket = row.dataset.ticket === '1';
            const matchesQuery = query === '' || haystack.indexOf(query) !== -1;
            const matchesSeverity = activeSeverities.size === 0 || activeSeverities.has(severity);
            const matchesTicketFilter =
                activeTicketFilter === 'all'
                || (activeTicketFilter === 'has' && hasTicket)
                || (activeTicketFilter === 'none' && !hasTicket);
            const show = matchesQuery && matchesSeverity && matchesTicketFilter;
            row.hidden = !show;
            if (!show) {
                const cb = row.querySelector('[data-nessus-vuln-row-check]');
                if (cb) {
                    cb.checked = false;
                }
            }
            if (show) {
                visible++;
            }
        }

        if (counter) counter.textContent = visible.toString();
        if (totalCounter) totalCounter.textContent = rows.length.toString();
        if (emptyState) emptyState.hidden = visible !== 0 || rows.length === 0;

        for (const card of sevCards) {
            const sev = card.dataset.nessusSevCard;
            card.setAttribute('aria-pressed', activeSeverities.has(sev) ? 'true' : 'false');
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

    if (ticketFilter) {
        ticketFilter.addEventListener('change', () => {
            activeTicketFilter = ticketFilter.value || 'all';
            applyFilter();
        });
    }

    for (const card of sevCards) {
        card.addEventListener('click', () => {
            const sev = card.dataset.nessusSevCard;
            if (!sev) return;
            if (activeSeverities.has(sev)) {
                activeSeverities.delete(sev);
            } else {
                activeSeverities.add(sev);
            }
            applyFilter();
        });
    }

    if (masterCheckbox) {
        masterCheckbox.addEventListener('change', () => {
            const target = masterCheckbox.checked;
            for (const row of visibleSelectableRows()) {
                const cb = row.querySelector('[data-nessus-vuln-row-check]');
                if (cb) {
                    cb.checked = target;
                }
            }
            updateSelectionBar();
        });
    }

    list && list.addEventListener('change', (event) => {
        if (event.target.matches('[data-nessus-vuln-row-check]')) {
            updateSelectionBar();
        }
    });

    root.addEventListener('click', (event) => {
        const copyTarget = event.target.closest('[data-nessus-copy]');
        if (copyTarget) {
            const value = copyTarget.getAttribute('data-nessus-copy');
            if (value) {
                event.preventDefault();
                copyText(value);
                copyTarget.classList.add('is-copied');
                const prev = copyTarget.getAttribute('title');
                copyTarget.setAttribute('title', 'Copied!');
                window.setTimeout(() => {
                    copyTarget.classList.remove('is-copied');
                    if (prev !== null) copyTarget.setAttribute('title', prev);
                    else copyTarget.removeAttribute('title');
                }, 1100);
            }
        }

        const bulkBtn = event.target.closest('[data-nessus-vuln-bulk]');
        if (bulkBtn && bulkForm) {
            event.preventDefault();
            const selected = checkedRows();
            if (selected.length === 0) {
                showToast({ type: 'warning', message: bulkBtn.dataset.emptyText || 'Select at least one vulnerability.' });
                return;
            }
            confirmModal({
                variant: 'info',
                title: bulkBtn.dataset.confirmTitle || 'Create tickets?',
                message: (bulkBtn.dataset.confirmMessage || 'A ticket will be created for %d vulnerabilities.').replace('%d', selected.length.toString()),
                confirmLabel: bulkBtn.dataset.confirmLabel || 'Create',
                cancelLabel: bulkBtn.dataset.cancelLabel || 'Cancel',
            }).then((confirmed) => {
                if (!confirmed) return;
                const submitMode = bulkBtn.dataset.submitMode || 'create_selected_tickets';
                const trigger = document.createElement('input');
                trigger.type = 'hidden';
                trigger.name = submitMode;
                trigger.value = '1';
                bulkForm.appendChild(trigger);
                bulkForm.submit();
            });
        }
    });

    root.addEventListener('submit', (event) => {
        const form = event.target.closest('[data-nessus-vuln-ticket-form]');
        if (!form) return;
        if (form.dataset.confirmed === '1') return;
        event.preventDefault();
        confirmModal({
            variant: 'info',
            title: form.dataset.confirmTitle || 'Create ticket?',
            message: form.dataset.confirmMessage || 'A ticket will be created for this vulnerability.',
            confirmLabel: form.dataset.confirmLabel || 'Create',
            cancelLabel: form.dataset.cancelLabel || 'Cancel',
        }).then((confirmed) => {
            if (!confirmed) return;
            form.dataset.confirmed = '1';
            form.submit();
        });
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
        try { document.execCommand('copy'); } catch (_e) {}
        document.body.removeChild(helper);
    }

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
        const iconInner = {
            success: '<path d="M20 6 9 17l-5-5"/>',
            warning: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/>',
            error: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
            info: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
        }[type] || '<circle cx="12" cy="12" r="10"/>';
        toast.innerHTML = '<span class="nessus-toast__icon">' + svg(iconInner) + '</span>'
            + '<div class="nessus-toast__body"></div>'
            + '<button type="button" class="nessus-toast__close" aria-label="Close">&times;</button>';
        toast.querySelector('.nessus-toast__body').textContent = opts.message || '';
        toast.querySelector('.nessus-toast__close').addEventListener('click', () => removeToast(toast));
        toastHost.appendChild(toast);
        window.requestAnimationFrame(() => toast.classList.add('is-visible'));
        const ttl = typeof opts.ttl === 'number' ? opts.ttl : 4200;
        if (ttl > 0) window.setTimeout(() => removeToast(toast), ttl);
    }

    function removeToast(toast) {
        toast.classList.remove('is-visible');
        window.setTimeout(() => toast.remove(), 280);
    }

    function svg(inner) {
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + '</svg>';
    }

    function confirmModal(opts) {
        return new Promise((resolve) => {
            if (activeModal) activeModal.dismiss();
            const variant = opts.variant === 'danger' ? 'danger' : 'info';
            const backdrop = document.createElement('div');
            backdrop.className = 'nessus-modal-backdrop';
            const modal = document.createElement('div');
            modal.className = 'nessus-modal nessus-modal--' + variant;
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            const iconSvg = variant === 'danger'
                ? svg('<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/>')
                : svg('<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/>');
            const confirmClass = variant === 'danger' ? 'nessus-btn-danger' : 'nessus-btn-primary';
            modal.innerHTML =
                '<div class="nessus-modal__header">'
                + '<div class="nessus-modal__icon">' + iconSvg + '</div>'
                + '<h3 class="nessus-modal__title"></h3></div>'
                + '<div class="nessus-modal__body"></div>'
                + '<div class="nessus-modal__footer">'
                + '<button type="button" class="nessus-btn-outline" data-action="cancel"></button>'
                + '<button type="button" class="' + confirmClass + '" data-action="confirm"></button>'
                + '</div>';
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
                window.setTimeout(() => { modal.remove(); backdrop.remove(); }, 200);
                document.removeEventListener('keydown', onKey);
                activeModal = null;
                resolve(result);
            }
            function onKey(event) {
                if (event.key === 'Escape') { event.preventDefault(); dismiss(false); }
                if (event.key === 'Enter') { event.preventDefault(); dismiss(true); }
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

    applyFilter();
})();

// Detail page enhancements — CVE chips with copy
(function () {
    'use strict';
    const root = document.querySelector('[data-nessus-vuln-detail]');
    if (!root) return;
    root.addEventListener('click', (event) => {
        const target = event.target.closest('[data-nessus-copy]');
        if (!target) return;
        const value = target.getAttribute('data-nessus-copy');
        if (!value) return;
        event.preventDefault();
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).catch(() => fallbackCopyInline(value));
        } else {
            fallbackCopyInline(value);
        }
        target.classList.add('is-copied');
        window.setTimeout(() => target.classList.remove('is-copied'), 1100);
    });
    function fallbackCopyInline(value) {
        const helper = document.createElement('textarea');
        helper.value = value;
        helper.setAttribute('readonly', '');
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        helper.style.left = '-9999px';
        document.body.appendChild(helper);
        helper.select();
        try { document.execCommand('copy'); } catch (_e) {}
        document.body.removeChild(helper);
    }
})();
