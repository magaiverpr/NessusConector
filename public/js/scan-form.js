(function () {
    'use strict';

    const page = document.querySelector('.nessus-scan-form-page[data-nessus-scan-form]');
    if (!page) {
        return;
    }

    let state;
    try {
        state = JSON.parse(page.getAttribute('data-nessus-scan-form') || '{}');
    } catch (_e) {
        state = {};
    }

    const i18n         = state.i18n || {};
    const placeholders = state.placeholders || {};
    const hints        = state.hints || {};
    const previewUrl   = state.previewUrl || '';

    const idInput       = page.querySelector('[data-nessus-scan-form-id]');
    const hintEl        = page.querySelector('[data-nessus-scan-form-hint]');
    const feedbackEl    = page.querySelector('[data-nessus-scan-form-feedback]');
    const verifyBtn     = page.querySelector('[data-nessus-scan-form-verify]');
    const previewEl     = page.querySelector('[data-nessus-scan-form-preview]');
    const previewName   = previewEl ? previewEl.querySelector('[data-nessus-scan-form-preview-name]') : null;
    const previewMeta   = previewEl ? previewEl.querySelector('[data-nessus-scan-form-preview-meta]') : null;
    const sourceInputs  = Array.from(page.querySelectorAll('[data-nessus-scan-form-source]'));

    const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    /* ------------------ Source switcher ------------------ */

    function getCurrentSource() {
        const selected = sourceInputs.find((r) => r.checked);
        return selected ? selected.value : 'nessus';
    }

    function updateSourceUI(source) {
        sourceInputs.forEach((input) => {
            const option = input.closest('.nessus-scan-form-source__option');
            if (!option) return;
            if (input.value === source) {
                option.setAttribute('data-active', 'true');
            } else {
                option.removeAttribute('data-active');
            }
        });

        if (idInput) {
            idInput.placeholder = placeholders[source] || '';
        }

        if (hintEl) {
            hintEl.textContent = hints[source] || '';
        }

        // Re-validate the existing value against the new source rules.
        if (idInput && idInput.value.trim() !== '') {
            validateScanId();
        } else {
            clearFeedback();
        }

        hidePreview();
    }

    sourceInputs.forEach((input) => {
        input.addEventListener('change', () => {
            if (input.checked) {
                updateSourceUI(input.value);
            }
        });
    });

    updateSourceUI(getCurrentSource());

    /* ------------------ Scan ID validation ------------------ */

    function setFeedback(message, variant) {
        if (!feedbackEl) return;
        if (!message) {
            feedbackEl.hidden = true;
            feedbackEl.textContent = '';
            feedbackEl.classList.remove('nessus-scan-form-feedback--success');
            return;
        }
        feedbackEl.hidden = false;
        feedbackEl.textContent = message;
        feedbackEl.classList.toggle('nessus-scan-form-feedback--success', variant === 'success');
    }

    function clearFeedback() {
        if (idInput) {
            idInput.removeAttribute('aria-invalid');
        }
        setFeedback('', null);
    }

    function validateScanId() {
        if (!idInput) return true;
        const value = idInput.value.trim();
        if (value === '') {
            clearFeedback();
            return true;
        }

        const source = getCurrentSource();
        let valid;
        let invalidMessage;

        if (source === 'was') {
            valid = UUID_PATTERN.test(value);
            invalidMessage = i18n.invalidUuid || 'WAS expects a UUID.';
        } else {
            valid = /^\d+$/.test(value);
            invalidMessage = i18n.invalidNumeric || 'Tenable VM expects a numeric ID.';
        }

        idInput.setAttribute('aria-invalid', valid ? 'false' : 'true');
        setFeedback(valid ? '' : invalidMessage, valid ? null : 'error');
        return valid;
    }

    if (idInput) {
        idInput.addEventListener('input', () => {
            // Clear stale preview once the user edits the ID.
            hidePreview();
            if (idInput.getAttribute('aria-invalid') === 'true') {
                validateScanId();
            }
        });
        idInput.addEventListener('blur', validateScanId);
    }

    /* ------------------ Verify on Tenable (AJAX preview) ------------------ */

    function hidePreview() {
        if (!previewEl) return;
        previewEl.hidden = true;
        if (previewName) previewName.textContent = '';
        if (previewMeta) previewMeta.innerHTML = '';
    }

    function showPreview(payload) {
        if (!previewEl) return;
        if (previewName) {
            previewName.textContent = String(payload.name || '');
        }
        if (previewMeta) {
            previewMeta.innerHTML = '';
            const meta = payload.meta || {};
            const labels = {
                targets:      i18n.previewLabelTargets || 'Targets',
                status:       i18n.previewLabelStatus || 'Status',
                folder:       i18n.previewLabelFolder || 'Folder',
                owner:        i18n.previewLabelOwner || 'Owner',
                last_updated: i18n.previewLabelLastUpdated || 'Last updated',
            };
            ['targets', 'status', 'folder', 'owner', 'last_updated'].forEach((key) => {
                if (!meta[key]) return;
                const dt = document.createElement('dt');
                dt.textContent = labels[key];
                const dd = document.createElement('dd');
                dd.textContent = String(meta[key]);
                previewMeta.appendChild(dt);
                previewMeta.appendChild(dd);
            });
        }
        previewEl.hidden = false;
    }

    if (verifyBtn) {
        verifyBtn.addEventListener('click', async () => {
            if (!idInput || !previewUrl) return;
            const value = idInput.value.trim();
            if (value === '') {
                setFeedback(i18n.previewEmpty || 'Enter a scan ID first.', 'error');
                idInput.focus();
                return;
            }
            if (!validateScanId()) {
                return;
            }

            verifyBtn.setAttribute('data-loading', 'true');
            verifyBtn.disabled = true;
            setFeedback(i18n.previewLoading || 'Querying Tenable…', 'success');
            hidePreview();

            const body = new FormData();
            body.set('scan_id', value);
            body.set('scan_type', getCurrentSource());
            if (state.csrf) {
                body.set('_glpi_csrf_token', state.csrf);
            }

            try {
                const response = await fetch(previewUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Accept': 'application/json' },
                    body,
                });
                let data = null;
                try { data = await response.json(); } catch (_e) { data = null; }

                if (data && data.ok) {
                    setFeedback(i18n.previewOk || 'Scan found.', 'success');
                    showPreview(data);
                } else {
                    setFeedback(
                        (data && data.message) ? data.message : (i18n.previewFailed || 'Unable to verify scan.'),
                        'error'
                    );
                }
            } catch (_err) {
                setFeedback(i18n.previewFailed || 'Unable to verify scan.', 'error');
            } finally {
                verifyBtn.removeAttribute('data-loading');
                verifyBtn.disabled = false;
            }
        });
    }
})();
