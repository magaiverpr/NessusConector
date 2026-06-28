(function () {
    'use strict';

    const root = document.querySelector('[data-nessus-browser]');
    if (!root) {
        return;
    }

    const searchInput = root.querySelector('[data-nessus-search]');
    const statusSelect = root.querySelector('[data-nessus-status-filter]');
    const grid = root.querySelector('[data-nessus-grid]');
    const cards = grid ? Array.from(grid.querySelectorAll('[data-nessus-card]')) : [];
    const emptyState = root.querySelector('[data-nessus-empty]');
    const visibleCounter = root.querySelector('[data-nessus-count]');
    const totalCounter = root.querySelector('[data-nessus-total]');
    const clearButton = root.querySelector('[data-nessus-clear]');

    const normalize = (value) => (value || '').toString().toLowerCase().trim();

    function applyFilter() {
        const query = normalize(searchInput ? searchInput.value : '');
        const status = statusSelect ? statusSelect.value : 'all';
        let visible = 0;

        for (const card of cards) {
            const haystack = card.dataset.haystack || '';
            const cardStatus = card.dataset.status || '';
            const matchesQuery = query === '' || haystack.indexOf(query) !== -1;
            const matchesStatus = status === 'all' || cardStatus === status;
            const show = matchesQuery && matchesStatus;
            card.hidden = !show;
            if (show) {
                visible++;
            }
        }

        if (visibleCounter) {
            visibleCounter.textContent = visible.toString();
        }
        if (totalCounter) {
            totalCounter.textContent = cards.length.toString();
        }
        if (emptyState) {
            const hasResults = visible > 0;
            emptyState.hidden = hasResults || cards.length === 0;
        }
        if (grid) {
            grid.classList.toggle('is-empty', visible === 0);
        }
        if (clearButton) {
            const hasFilters = query !== '' || status !== 'all';
            clearButton.hidden = !hasFilters;
        }
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

    if (statusSelect) {
        statusSelect.addEventListener('change', applyFilter);
    }

    if (clearButton) {
        clearButton.addEventListener('click', (event) => {
            event.preventDefault();
            if (searchInput) {
                searchInput.value = '';
            }
            if (statusSelect) {
                statusSelect.value = 'all';
            }
            applyFilter();
            if (searchInput) {
                searchInput.focus();
            }
        });
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

    function flashCopied(target) {
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
        }, 1200);
    }

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

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).catch(() => fallbackCopy(value));
        } else {
            fallbackCopy(value);
        }
        flashCopied(target);
    });

    applyFilter();
})();
