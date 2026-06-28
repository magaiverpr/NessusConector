(function () {
    'use strict';

    const page = document.querySelector('.nessus-config-page[data-nessus-config]');
    if (!page) {
        return;
    }

    let state;
    try {
        state = JSON.parse(page.getAttribute('data-nessus-config') || '{}');
    } catch (err) {
        state = {};
    }

    const i18n = state.i18n || {};
    const ajaxUrl = state.ajaxUrl || '';
    const csrfToken = state.csrf || '';

    const form = page.querySelector('form.nessus-config-form');
    if (!form) {
        return;
    }

    /* ------------------ Secret toggles ------------------ */

    page.querySelectorAll('[data-nessus-secret-toggle]').forEach((btn) => {
        const wrapper = btn.closest('.nessus-config-secret');
        if (!wrapper) {
            return;
        }
        const input = wrapper.querySelector('[data-nessus-secret-input]');
        if (!input) {
            return;
        }

        btn.setAttribute(
            'title',
            i18n.showSecret || 'Show secret'
        );

        btn.addEventListener('click', () => {
            const revealed = wrapper.getAttribute('data-revealed') === 'true';
            if (revealed) {
                wrapper.removeAttribute('data-revealed');
                input.type = 'password';
                btn.setAttribute('title', i18n.showSecret || 'Show secret');
                btn.setAttribute('aria-pressed', 'false');
            } else {
                wrapper.setAttribute('data-revealed', 'true');
                input.type = 'text';
                btn.setAttribute('title', i18n.hideSecret || 'Hide secret');
                btn.setAttribute('aria-pressed', 'true');
            }
        });
    });

    /* ------------------ URL validation ------------------ */

    const URL_PATTERN = /^https?:\/\/[^\s/$.?#][^\s]*$/i;

    page.querySelectorAll('[data-nessus-config-input="url"]').forEach((input) => {
        const field = input.closest('.nessus-config-field');
        const feedback = field ? field.querySelector('[data-nessus-field-feedback]') : null;

        const validate = () => {
            const value = (input.value || '').trim();
            if (value === '') {
                input.removeAttribute('aria-invalid');
                if (feedback) {
                    feedback.hidden = true;
                    feedback.textContent = '';
                }
                return true;
            }
            const valid = URL_PATTERN.test(value);
            input.setAttribute('aria-invalid', valid ? 'false' : 'true');
            if (feedback) {
                if (!valid) {
                    feedback.hidden = false;
                    feedback.textContent = i18n.invalidUrl || 'Invalid URL';
                } else {
                    feedback.hidden = true;
                    feedback.textContent = '';
                }
            }
            return valid;
        };

        input.addEventListener('blur', validate);
        input.addEventListener('input', () => {
            if (input.getAttribute('aria-invalid') === 'true') {
                validate();
            }
        });
    });

    /* ------------------ Test connection (AJAX) ------------------ */

    function collectFormPayload() {
        const formData = new FormData(form);
        if (csrfToken && !formData.get('_glpi_csrf_token')) {
            formData.set('_glpi_csrf_token', csrfToken);
        }
        return formData;
    }

    function setPill(card, variant, label, latencyMs) {
        const pill = card.querySelector('[data-nessus-conn-status]');
        if (!pill) {
            return;
        }
        pill.classList.remove(
            'nessus-conn-pill--muted',
            'nessus-conn-pill--testing',
            'nessus-conn-pill--success',
            'nessus-conn-pill--danger'
        );
        pill.classList.add('nessus-conn-pill--' + variant);

        const labelEl = pill.querySelector('.nessus-conn-pill__label');
        if (labelEl) {
            labelEl.textContent = label;
        }

        const latencyEl = pill.querySelector('.nessus-conn-pill__latency');
        if (latencyEl) {
            if (typeof latencyMs === 'number' && latencyMs >= 0) {
                const tmpl = i18n.latency || '%d ms';
                latencyEl.textContent = tmpl.replace('%d', String(latencyMs));
                latencyEl.hidden = false;
            } else {
                latencyEl.textContent = '';
                latencyEl.hidden = true;
            }
        }
    }

    function setMessage(card, variant, message) {
        const box = card.querySelector('[data-nessus-conn-message]');
        if (!box) {
            return;
        }
        box.classList.remove('nessus-conn-message--success', 'nessus-conn-message--danger');
        if (!message) {
            box.hidden = true;
            box.textContent = '';
            return;
        }
        box.classList.add('nessus-conn-message--' + variant);
        const icon = variant === 'success'
            ? '<span class="nessus-conn-message__icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></span>'
            : '<span class="nessus-conn-message__icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></span>';
        box.innerHTML = icon + '<span>' + escapeHtml(message) + '</span>';
        box.hidden = false;
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, (ch) => {
            switch (ch) {
                case '&': return '&amp;';
                case '<': return '&lt;';
                case '>': return '&gt;';
                case '"': return '&quot;';
                case "'": return '&#39;';
                default: return ch;
            }
        });
    }

    page.querySelectorAll('[data-nessus-test-btn]').forEach((btn) => {
        const provider = btn.getAttribute('data-nessus-test-btn');
        const card = btn.closest('[data-nessus-config-card]');
        if (!card || !provider) {
            return;
        }

        btn.addEventListener('click', async () => {
            if (btn.disabled || !ajaxUrl) {
                return;
            }

            setPill(card, 'testing', i18n.testing || 'Testing connection…', null);
            setMessage(card, null, '');
            btn.setAttribute('data-loading', 'true');
            btn.disabled = true;

            const payload = collectFormPayload();
            payload.set('provider', provider);

            try {
                const response = await fetch(ajaxUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    body: payload,
                    headers: {
                        'Accept': 'application/json',
                        // Mark as AJAX so GLPI reads the CSRF token from the
                        // X-Glpi-Csrf-Token header and validates it with
                        // preserve_token: true. Without this, GLPI treats the
                        // request as a normal form POST and consumes the form's
                        // single-use token, which then breaks repeated tests and
                        // the subsequent Save (HTTP 403 "CSRF check failed").
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-Glpi-Csrf-Token': csrfToken,
                    },
                });

                let data = null;
                try {
                    data = await response.json();
                } catch (e) {
                    data = null;
                }

                if (data && typeof data === 'object') {
                    const latency = typeof data.latency_ms === 'number' ? data.latency_ms : null;
                    if (data.ok) {
                        setPill(card, 'success', i18n.success || 'Connection OK', latency);
                        setMessage(card, 'success', String(data.message || ''));
                    } else {
                        setPill(card, 'danger', i18n.failed || 'Connection failed', latency);
                        setMessage(card, 'danger', String(data.message || (i18n.networkError || 'Network error')));
                    }
                } else {
                    setPill(card, 'danger', i18n.failed || 'Connection failed', null);
                    setMessage(card, 'danger', i18n.networkError || 'Network error');
                }
            } catch (err) {
                setPill(card, 'danger', i18n.failed || 'Connection failed', null);
                setMessage(card, 'danger', i18n.networkError || 'Network error');
            } finally {
                btn.removeAttribute('data-loading');
                btn.disabled = false;
            }
        });
    });
})();
