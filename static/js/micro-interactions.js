/**
 * Zumodra Micro-Interactions Module
 *
 * Subtle animations and feedback for user actions:
 * - Ripple effects on buttons
 * - Hover animations
 * - Success/error feedback
 * - Toast notifications
 * - Tooltip handling
 */

(function() {
    'use strict';

    /**
     * Ripple Effect - Material-style button ripples
     */
    const RippleEffect = {
        init() {
            document.addEventListener('click', (e) => {
                const target = e.target.closest('[data-ripple], .btn:not([data-ripple="false"])');
                if (!target) return;

                // Respect reduced motion preference
                if (window.ZumodraA11y?.prefersReducedMotion?.()) return;

                this.create(e, target);
            });
        },

        create(event, element) {
            const ripple = document.createElement('span');
            ripple.classList.add('ripple-effect');

            const rect = element.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);

            ripple.style.width = ripple.style.height = `${size}px`;
            ripple.style.left = `${event.clientX - rect.left - size / 2}px`;
            ripple.style.top = `${event.clientY - rect.top - size / 2}px`;

            element.style.position = 'relative';
            element.style.overflow = 'hidden';
            element.appendChild(ripple);

            // Remove after animation
            ripple.addEventListener('animationend', () => ripple.remove());
        }
    };

    /**
     * Toast Notifications - Non-blocking notifications
     */
    const Toast = {
        container: null,

        init() {
            this.createContainer();
        },

        createContainer() {
            if (this.container) return;

            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.setAttribute('aria-live', 'polite');
            this.container.setAttribute('aria-atomic', 'false');
            document.body.appendChild(this.container);
        },

        /**
         * Show a toast notification
         * @param {string} message - Message to display
         * @param {Object} options - Toast options
         */
        show(message, options = {}) {
            if (!this.container) this.createContainer();

            const {
                type = 'info', // 'success', 'error', 'warning', 'info'
                duration = 5000,
                action = null, // { text: 'Undo', handler: () => {} }
                dismissible = true
            } = options;

            const toast = document.createElement('div');
            toast.classList.add('toast', `toast-${type}`);
            toast.setAttribute('role', 'alert');

            const icons = {
                success: '&#10003;',
                error: '&#10007;',
                warning: '&#9888;',
                info: '&#8505;'
            };

            toast.innerHTML = `
                <span class="toast-icon" aria-hidden="true">${icons[type] || icons.info}</span>
                <span class="toast-message">${message}</span>
                ${action ? `<button type="button" class="toast-action">${action.text}</button>` : ''}
                ${dismissible ? '<button type="button" class="toast-close" aria-label="Close">&times;</button>' : ''}
            `;

            // Setup action button
            if (action) {
                const actionBtn = toast.querySelector('.toast-action');
                actionBtn.addEventListener('click', () => {
                    action.handler();
                    this.dismiss(toast);
                });
            }

            // Setup close button
            if (dismissible) {
                const closeBtn = toast.querySelector('.toast-close');
                closeBtn.addEventListener('click', () => this.dismiss(toast));
            }

            // Add to container
            this.container.appendChild(toast);

            // Trigger entrance animation
            requestAnimationFrame(() => toast.classList.add('toast-visible'));

            // Auto-dismiss
            if (duration > 0) {
                setTimeout(() => this.dismiss(toast), duration);
            }

            // Announce to screen readers
            if (window.ZumodraA11y?.announce) {
                const priority = type === 'error' ? 'assertive' : 'polite';
                window.ZumodraA11y.announce(message, priority);
            }

            return toast;
        },

        dismiss(toast) {
            if (!toast || !toast.parentNode) return;

            toast.classList.remove('toast-visible');
            toast.classList.add('toast-exiting');

            toast.addEventListener('animationend', () => toast.remove());
        },

        // Convenience methods
        success(message, options = {}) {
            return this.show(message, { ...options, type: 'success' });
        },

        error(message, options = {}) {
            return this.show(message, { ...options, type: 'error' });
        },

        warning(message, options = {}) {
            return this.show(message, { ...options, type: 'warning' });
        },

        info(message, options = {}) {
            return this.show(message, { ...options, type: 'info' });
        }
    };

    /**
     * Tooltip - Lightweight tooltip system
     */
    const Tooltip = {
        activeTooltip: null,

        init() {
            this.setupHoverListeners();
            this.setupFocusListeners();
        },

        setupHoverListeners() {
            document.addEventListener('mouseenter', (e) => {
                const trigger = e.target.closest('[data-tooltip]');
                if (trigger) this.show(trigger);
            }, true);

            document.addEventListener('mouseleave', (e) => {
                const trigger = e.target.closest('[data-tooltip]');
                if (trigger) this.hide();
            }, true);
        },

        setupFocusListeners() {
            document.addEventListener('focusin', (e) => {
                const trigger = e.target.closest('[data-tooltip]');
                if (trigger) this.show(trigger);
            });

            document.addEventListener('focusout', (e) => {
                const trigger = e.target.closest('[data-tooltip]');
                if (trigger) this.hide();
            });
        },

        show(trigger) {
            const text = trigger.getAttribute('data-tooltip');
            if (!text) return;

            this.hide();

            const tooltip = document.createElement('div');
            tooltip.classList.add('tooltip');
            tooltip.setAttribute('role', 'tooltip');
            tooltip.textContent = text;

            document.body.appendChild(tooltip);

            // Position tooltip
            const rect = trigger.getBoundingClientRect();
            const position = trigger.getAttribute('data-tooltip-position') || 'top';

            this.position(tooltip, rect, position);

            // Show with animation
            requestAnimationFrame(() => tooltip.classList.add('tooltip-visible'));

            this.activeTooltip = tooltip;

            // Link for accessibility
            const id = `tooltip-${Date.now()}`;
            tooltip.id = id;
            trigger.setAttribute('aria-describedby', id);
        },

        position(tooltip, triggerRect, position) {
            const gap = 8;

            switch (position) {
                case 'top':
                    tooltip.style.left = `${triggerRect.left + triggerRect.width / 2}px`;
                    tooltip.style.top = `${triggerRect.top - gap}px`;
                    tooltip.style.transform = 'translate(-50%, -100%)';
                    break;
                case 'bottom':
                    tooltip.style.left = `${triggerRect.left + triggerRect.width / 2}px`;
                    tooltip.style.top = `${triggerRect.bottom + gap}px`;
                    tooltip.style.transform = 'translate(-50%, 0)';
                    break;
                case 'left':
                    tooltip.style.left = `${triggerRect.left - gap}px`;
                    tooltip.style.top = `${triggerRect.top + triggerRect.height / 2}px`;
                    tooltip.style.transform = 'translate(-100%, -50%)';
                    break;
                case 'right':
                    tooltip.style.left = `${triggerRect.right + gap}px`;
                    tooltip.style.top = `${triggerRect.top + triggerRect.height / 2}px`;
                    tooltip.style.transform = 'translate(0, -50%)';
                    break;
            }
        },

        hide() {
            if (this.activeTooltip) {
                this.activeTooltip.remove();
                this.activeTooltip = null;

                // Clean up aria-describedby
                document.querySelectorAll('[aria-describedby^="tooltip-"]').forEach(el => {
                    el.removeAttribute('aria-describedby');
                });
            }
        }
    };

    /**
     * Feedback Animations - Success/error states
     */
    const Feedback = {
        /**
         * Show success feedback on element
         * @param {HTMLElement} element - Target element
         */
        success(element) {
            this.animate(element, 'feedback-success');
        },

        /**
         * Show error feedback on element
         * @param {HTMLElement} element - Target element
         */
        error(element) {
            this.animate(element, 'feedback-error');
        },

        /**
         * Shake animation for errors
         * @param {HTMLElement} element - Target element
         */
        shake(element) {
            this.animate(element, 'feedback-shake');
        },

        /**
         * Pulse animation for attention
         * @param {HTMLElement} element - Target element
         */
        pulse(element) {
            this.animate(element, 'feedback-pulse');
        },

        animate(element, className) {
            // Respect reduced motion
            if (window.ZumodraA11y?.prefersReducedMotion?.()) {
                element.classList.add(className.replace('feedback-', 'static-'));
                setTimeout(() => element.classList.remove(className.replace('feedback-', 'static-')), 300);
                return;
            }

            element.classList.add(className);
            element.addEventListener('animationend', () => {
                element.classList.remove(className);
            }, { once: true });
        }
    };

    /**
     * Scroll Animations - Animate elements on scroll
     */
    const ScrollAnimations = {
        observer: null,

        init() {
            if (!('IntersectionObserver' in window)) return;
            if (window.ZumodraA11y?.prefersReducedMotion?.()) return;

            this.observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('scroll-visible');
                        this.observer.unobserve(entry.target);
                    }
                });
            }, {
                threshold: 0.1,
                rootMargin: '50px'
            });

            document.querySelectorAll('[data-scroll-animate]').forEach(el => {
                this.observer.observe(el);
            });
        }
    };

    /**
     * Counter Animation - Animate number counting
     */
    const Counter = {
        /**
         * Animate a number counter
         * @param {HTMLElement} element - Element to animate
         * @param {number} target - Target number
         * @param {number} duration - Animation duration in ms
         */
        animate(element, target, duration = 1000) {
            // Respect reduced motion
            if (window.ZumodraA11y?.prefersReducedMotion?.()) {
                element.textContent = target.toLocaleString();
                return;
            }

            const start = parseInt(element.textContent.replace(/,/g, '')) || 0;
            const range = target - start;
            const startTime = performance.now();

            const step = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);

                // Ease-out cubic
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = Math.round(start + range * eased);

                element.textContent = current.toLocaleString();

                if (progress < 1) {
                    requestAnimationFrame(step);
                }
            };

            requestAnimationFrame(step);
        }
    };

    // Initialize all modules
    function init() {
        RippleEffect.init();
        Toast.init();
        Tooltip.init();
        ScrollAnimations.init();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose globally
    window.ZumodraUI = {
        Toast,
        Tooltip,
        Feedback,
        Counter
    };

})();
