/**
 * Micro-Interactions for Zumodra
 *
 * Features:
 * - Button ripple effect
 * - Card hover lift
 * - Success checkmark animation
 * - Error shake animation
 * - Toast slide-in/out
 * - Smooth transitions respecting reduced motion
 *
 * WCAG 2.1 AA Compliant
 */

(function() {
    'use strict';

    // Constants
    const ANIMATION_DURATION = 300;
    const RIPPLE_DURATION = 600;

    /**
     * Check if reduced motion is preferred
     * @returns {boolean}
     */
    function prefersReducedMotion() {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    /**
     * Get appropriate animation duration
     * @param {number} normalDuration - Normal duration in ms
     * @returns {number} Duration respecting user preference
     */
    function getAnimationDuration(normalDuration) {
        return prefersReducedMotion() ? 0 : normalDuration;
    }

    /**
     * Ripple Effect
     * Creates a Material Design-inspired ripple effect on click
     */
    const RippleEffect = {
        /**
         * Initialize ripple effect on elements
         * @param {string|NodeList|HTMLElement} selector - Elements to apply ripple to
         */
        init(selector = '.btn, .ripple, [data-ripple]') {
            const elements = typeof selector === 'string'
                ? document.querySelectorAll(selector)
                : (selector instanceof NodeList ? selector : [selector]);

            elements.forEach(el => this.attach(el));
        },

        /**
         * Attach ripple effect to an element
         * @param {HTMLElement} element - Target element
         */
        attach(element) {
            if (!element || element.dataset.rippleAttached) return;

            element.style.position = 'relative';
            element.style.overflow = 'hidden';
            element.dataset.rippleAttached = 'true';

            element.addEventListener('mousedown', (e) => this.create(e, element));
            element.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    const rect = element.getBoundingClientRect();
                    this.create({
                        clientX: rect.left + rect.width / 2,
                        clientY: rect.top + rect.height / 2
                    }, element);
                }
            });
        },

        /**
         * Create ripple element
         * @param {Event} event - Mouse or keyboard event
         * @param {HTMLElement} container - Container element
         */
        create(event, container) {
            if (prefersReducedMotion()) {
                // Subtle highlight instead of ripple
                container.style.opacity = '0.8';
                setTimeout(() => {
                    container.style.opacity = '';
                }, 150);
                return;
            }

            const rect = container.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height) * 2;

            const ripple = document.createElement('span');
            ripple.className = 'ripple-effect';
            ripple.setAttribute('aria-hidden', 'true');

            const x = event.clientX - rect.left - size / 2;
            const y = event.clientY - rect.top - size / 2;

            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${x}px;
                top: ${y}px;
                background: currentColor;
                opacity: 0.2;
                border-radius: 50%;
                transform: scale(0);
                pointer-events: none;
                animation: ripple-expand ${RIPPLE_DURATION}ms ease-out forwards;
            `;

            container.appendChild(ripple);

            setTimeout(() => {
                ripple.remove();
            }, RIPPLE_DURATION);
        }
    };

    /**
     * Card Hover Lift Effect
     * Adds subtle lift and shadow on hover
     */
    const CardLift = {
        /**
         * Initialize lift effect on cards
         * @param {string} selector - Card selector
         */
        init(selector = '.card, .card-lift, [data-lift]') {
            const cards = document.querySelectorAll(selector);
            cards.forEach(card => this.attach(card));
        },

        /**
         * Attach lift effect to a card
         * @param {HTMLElement} card - Card element
         */
        attach(card) {
            if (!card || card.dataset.liftAttached) return;

            card.dataset.liftAttached = 'true';

            // Store original styles
            const originalTransform = card.style.transform || 'translateY(0)';
            const originalShadow = card.style.boxShadow || 'var(--shadow-sm)';

            const duration = getAnimationDuration(ANIMATION_DURATION);
            card.style.transition = `transform ${duration}ms ease, box-shadow ${duration}ms ease`;

            card.addEventListener('mouseenter', () => {
                if (!prefersReducedMotion()) {
                    card.style.transform = 'translateY(-4px)';
                    card.style.boxShadow = 'var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.1))';
                }
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = originalTransform;
                card.style.boxShadow = originalShadow;
            });

            // Focus support for keyboard navigation
            card.addEventListener('focusin', () => {
                if (!prefersReducedMotion()) {
                    card.style.transform = 'translateY(-4px)';
                    card.style.boxShadow = 'var(--shadow-lg)';
                }
            });

            card.addEventListener('focusout', () => {
                card.style.transform = originalTransform;
                card.style.boxShadow = originalShadow;
            });
        }
    };

    /**
     * Success Animation
     * Shows an animated checkmark for success states
     */
    const SuccessAnimation = {
        /**
         * Show success checkmark
         * @param {HTMLElement} container - Container to show animation in
         * @param {Object} options - Configuration options
         * @returns {Promise} Resolves when animation completes
         */
        show(container, options = {}) {
            return new Promise((resolve) => {
                const {
                    size = 48,
                    color = 'var(--brand-success, #198754)',
                    duration = prefersReducedMotion() ? 0 : 600,
                    autoRemove = true,
                    removeDelay = 1500
                } = options;

                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('viewBox', '0 0 52 52');
                svg.setAttribute('width', size);
                svg.setAttribute('height', size);
                svg.setAttribute('aria-hidden', 'true');
                svg.className = 'success-checkmark';

                svg.innerHTML = `
                    <circle class="success-checkmark__circle" cx="26" cy="26" r="25" fill="none" stroke="${color}" stroke-width="2" />
                    <path class="success-checkmark__check" fill="none" stroke="${color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
                `;

                if (!prefersReducedMotion()) {
                    svg.style.cssText = `
                        animation: success-scale ${duration}ms ease forwards;
                    `;
                }

                container.appendChild(svg);

                // Announce for screen readers
                if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                    window.ZumodraA11y.Announcer.polite('Success');
                }

                setTimeout(() => {
                    if (autoRemove) {
                        svg.style.opacity = '0';
                        setTimeout(() => svg.remove(), ANIMATION_DURATION);
                    }
                    resolve(svg);
                }, duration + removeDelay);
            });
        }
    };

    /**
     * Error Shake Animation
     * Shakes an element to indicate an error
     */
    const ErrorShake = {
        /**
         * Apply shake animation to element
         * @param {HTMLElement} element - Element to shake
         * @param {Object} options - Configuration options
         * @returns {Promise} Resolves when animation completes
         */
        shake(element, options = {}) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                const {
                    intensity = 10,
                    duration = prefersReducedMotion() ? 0 : 400
                } = options;

                if (prefersReducedMotion()) {
                    // Visual feedback without motion
                    element.style.outline = '2px solid var(--brand-danger, #dc3545)';
                    setTimeout(() => {
                        element.style.outline = '';
                        resolve();
                    }, 500);
                    return;
                }

                element.classList.add('is-shaking');
                element.style.animation = `shake ${duration}ms ease`;
                element.style.setProperty('--shake-intensity', `${intensity}px`);

                // Announce for screen readers
                if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                    window.ZumodraA11y.Announcer.assertive('Error');
                }

                setTimeout(() => {
                    element.style.animation = '';
                    element.classList.remove('is-shaking');
                    resolve();
                }, duration);
            });
        },

        /**
         * Apply shake to form field on validation error
         * @param {HTMLElement} field - Form field
         * @param {string} message - Error message
         */
        shakeField(field, message = '') {
            this.shake(field);

            // Add error styling
            field.classList.add('is-invalid');
            field.setAttribute('aria-invalid', 'true');

            // Show error message if provided
            if (message) {
                let errorEl = field.parentNode.querySelector('.error-message');
                if (!errorEl) {
                    errorEl = document.createElement('div');
                    errorEl.className = 'error-message';
                    errorEl.id = `${field.id || 'field'}-error`;
                    errorEl.setAttribute('role', 'alert');
                    field.parentNode.appendChild(errorEl);
                    field.setAttribute('aria-describedby', errorEl.id);
                }
                errorEl.textContent = message;
            }
        }
    };

    /**
     * Toast Notifications
     * Slide-in/out toast messages
     */
    const Toast = {
        container: null,

        /**
         * Initialize toast container
         */
        init() {
            if (this.container) return;

            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.setAttribute('role', 'region');
            this.container.setAttribute('aria-label', 'Notifications');
            this.container.style.cssText = `
                position: fixed;
                bottom: 1rem;
                right: 1rem;
                z-index: 10000;
                display: flex;
                flex-direction: column-reverse;
                gap: 0.5rem;
                max-height: 100vh;
                overflow: hidden;
                pointer-events: none;
            `;

            document.body.appendChild(this.container);
        },

        /**
         * Show a toast notification
         * @param {Object} options - Toast configuration
         * @returns {HTMLElement} Toast element
         */
        show(options = {}) {
            this.init();

            const {
                message = '',
                type = 'info', // info, success, warning, error
                duration = 5000,
                dismissible = true,
                icon = null,
                action = null,
                actionText = 'Undo'
            } = options;

            const toast = document.createElement('div');
            toast.className = `toast toast--${type}`;
            toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
            toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
            toast.setAttribute('aria-atomic', 'true');

            const icons = {
                info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
                success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
                warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'
            };

            const colors = {
                info: { bg: '#e8f4fd', border: '#0dcaf0', text: '#055160' },
                success: { bg: '#d1e7dd', border: '#198754', text: '#0a3622' },
                warning: { bg: '#fff3cd', border: '#ffc107', text: '#664d03' },
                error: { bg: '#f8d7da', border: '#dc3545', text: '#58151c' }
            };

            const color = colors[type] || colors.info;

            toast.style.cssText = `
                display: flex;
                align-items: flex-start;
                gap: 0.75rem;
                padding: 1rem;
                background: ${color.bg};
                border-left: 4px solid ${color.border};
                border-radius: 8px;
                box-shadow: var(--shadow-lg, 0 10px 15px rgba(0, 0, 0, 0.1));
                color: ${color.text};
                font-size: 0.875rem;
                max-width: 400px;
                pointer-events: auto;
                transform: translateX(120%);
                opacity: 0;
                transition: transform ${getAnimationDuration(ANIMATION_DURATION)}ms ease, opacity ${getAnimationDuration(ANIMATION_DURATION)}ms ease;
            `;

            toast.innerHTML = `
                <span class="toast__icon" aria-hidden="true">${icon || icons[type]}</span>
                <div class="toast__content" style="flex: 1;">
                    <p class="toast__message" style="margin: 0;">${message}</p>
                    ${action ? `<button class="toast__action" style="margin-top: 0.5rem; padding: 0.25rem 0.5rem; background: transparent; border: 1px solid currentColor; border-radius: 4px; color: inherit; cursor: pointer; font-size: 0.75rem;">${actionText}</button>` : ''}
                </div>
                ${dismissible ? `<button class="toast__dismiss" aria-label="Dismiss notification" style="background: none; border: none; padding: 0.25rem; cursor: pointer; color: inherit; opacity: 0.7;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}
            `;

            this.container.appendChild(toast);

            // Slide in
            requestAnimationFrame(() => {
                toast.style.transform = 'translateX(0)';
                toast.style.opacity = '1';
            });

            // Dismiss button
            const dismissBtn = toast.querySelector('.toast__dismiss');
            if (dismissBtn) {
                dismissBtn.addEventListener('click', () => this.dismiss(toast));
            }

            // Action button
            const actionBtn = toast.querySelector('.toast__action');
            if (actionBtn && action) {
                actionBtn.addEventListener('click', () => {
                    action();
                    this.dismiss(toast);
                });
            }

            // Auto dismiss
            if (duration > 0) {
                setTimeout(() => this.dismiss(toast), duration);
            }

            return toast;
        },

        /**
         * Dismiss a toast
         * @param {HTMLElement} toast - Toast element
         */
        dismiss(toast) {
            if (!toast || toast.classList.contains('is-dismissing')) return;

            toast.classList.add('is-dismissing');
            toast.style.transform = 'translateX(120%)';
            toast.style.opacity = '0';

            setTimeout(() => {
                toast.remove();
            }, getAnimationDuration(ANIMATION_DURATION));
        },

        /**
         * Convenience methods
         */
        info(message, options = {}) {
            return this.show({ ...options, message, type: 'info' });
        },

        success(message, options = {}) {
            return this.show({ ...options, message, type: 'success' });
        },

        warning(message, options = {}) {
            return this.show({ ...options, message, type: 'warning' });
        },

        error(message, options = {}) {
            return this.show({ ...options, message, type: 'error' });
        }
    };

    /**
     * Fade Transition
     * Utility for smooth fade in/out
     */
    const Fade = {
        /**
         * Fade in an element
         * @param {HTMLElement} element - Element to fade in
         * @param {number} duration - Duration in ms
         * @returns {Promise}
         */
        in(element, duration = ANIMATION_DURATION) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = getAnimationDuration(duration);
                element.style.opacity = '0';
                element.style.display = '';
                element.style.transition = `opacity ${duration}ms ease`;

                requestAnimationFrame(() => {
                    element.style.opacity = '1';
                    setTimeout(resolve, duration);
                });
            });
        },

        /**
         * Fade out an element
         * @param {HTMLElement} element - Element to fade out
         * @param {number} duration - Duration in ms
         * @param {boolean} hide - Whether to hide after fade
         * @returns {Promise}
         */
        out(element, duration = ANIMATION_DURATION, hide = true) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = getAnimationDuration(duration);
                element.style.transition = `opacity ${duration}ms ease`;
                element.style.opacity = '0';

                setTimeout(() => {
                    if (hide) {
                        element.style.display = 'none';
                    }
                    resolve();
                }, duration);
            });
        }
    };

    /**
     * Slide Transition
     * Utility for slide animations
     */
    const Slide = {
        /**
         * Slide down to reveal content
         * @param {HTMLElement} element - Element to reveal
         * @param {number} duration - Duration in ms
         * @returns {Promise}
         */
        down(element, duration = ANIMATION_DURATION) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = getAnimationDuration(duration);

                // Get natural height
                element.style.display = '';
                element.style.height = 'auto';
                element.style.overflow = 'hidden';
                const height = element.offsetHeight;

                // Start from 0
                element.style.height = '0';
                element.style.transition = `height ${duration}ms ease`;

                requestAnimationFrame(() => {
                    element.style.height = `${height}px`;

                    setTimeout(() => {
                        element.style.height = '';
                        element.style.overflow = '';
                        resolve();
                    }, duration);
                });
            });
        },

        /**
         * Slide up to hide content
         * @param {HTMLElement} element - Element to hide
         * @param {number} duration - Duration in ms
         * @returns {Promise}
         */
        up(element, duration = ANIMATION_DURATION) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = getAnimationDuration(duration);

                element.style.height = `${element.offsetHeight}px`;
                element.style.overflow = 'hidden';
                element.style.transition = `height ${duration}ms ease`;

                requestAnimationFrame(() => {
                    element.style.height = '0';

                    setTimeout(() => {
                        element.style.display = 'none';
                        element.style.height = '';
                        element.style.overflow = '';
                        resolve();
                    }, duration);
                });
            });
        },

        /**
         * Toggle slide
         * @param {HTMLElement} element - Element to toggle
         * @param {number} duration - Duration in ms
         * @returns {Promise}
         */
        toggle(element, duration = ANIMATION_DURATION) {
            if (!element) return Promise.resolve();

            const isHidden = element.offsetHeight === 0 ||
                           getComputedStyle(element).display === 'none';

            return isHidden ? this.down(element, duration) : this.up(element, duration);
        }
    };

    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple-expand {
            to {
                transform: scale(1);
                opacity: 0;
            }
        }

        @keyframes success-scale {
            0% {
                transform: scale(0);
                opacity: 0;
            }
            50% {
                transform: scale(1.1);
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(calc(var(--shake-intensity, 10px) * -1)); }
            20%, 40%, 60%, 80% { transform: translateX(var(--shake-intensity, 10px)); }
        }

        .success-checkmark__circle {
            stroke-dasharray: 166;
            stroke-dashoffset: 166;
            animation: stroke-circle 0.6s cubic-bezier(0.65, 0, 0.45, 1) forwards;
        }

        .success-checkmark__check {
            stroke-dasharray: 48;
            stroke-dashoffset: 48;
            animation: stroke-check 0.3s cubic-bezier(0.65, 0, 0.45, 1) 0.4s forwards;
        }

        @keyframes stroke-circle {
            100% { stroke-dashoffset: 0; }
        }

        @keyframes stroke-check {
            100% { stroke-dashoffset: 0; }
        }

        /* Dark mode toast adjustments */
        [data-theme="dark"] .toast--info {
            background: rgba(13, 202, 240, 0.15);
            border-color: #39c0ed;
            color: #7dd3f0;
        }

        [data-theme="dark"] .toast--success {
            background: rgba(25, 135, 84, 0.15);
            border-color: #28a745;
            color: #75d99e;
        }

        [data-theme="dark"] .toast--warning {
            background: rgba(255, 193, 7, 0.15);
            border-color: #ffda6a;
            color: #ffda6a;
        }

        [data-theme="dark"] .toast--error {
            background: rgba(220, 53, 69, 0.15);
            border-color: #f85149;
            color: #ff8589;
        }

        /* Reduced motion */
        @media (prefers-reduced-motion: reduce) {
            .ripple-effect,
            .success-checkmark,
            .success-checkmark__circle,
            .success-checkmark__check {
                animation: none !important;
            }

            .success-checkmark__circle {
                stroke-dashoffset: 0;
            }

            .success-checkmark__check {
                stroke-dashoffset: 0;
            }

            .toast {
                transform: none !important;
            }
        }
    `;
    document.head.appendChild(style);

    // Auto-initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            RippleEffect.init();
            CardLift.init();
        });
    } else {
        RippleEffect.init();
        CardLift.init();
    }

    // Expose to global scope
    window.ZumodraMicro = {
        Ripple: RippleEffect,
        CardLift,
        Success: SuccessAnimation,
        ErrorShake,
        Toast,
        Fade,
        Slide,
        getAnimationDuration,
        prefersReducedMotion
    };

    // Dispatch ready event
    window.dispatchEvent(new CustomEvent('zumodra:micro-ready'));

})();
