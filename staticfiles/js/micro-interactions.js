/**
 * Zumodra Micro-Interactions System
 *
 * Orchestrated motion language for a distinctive, memorable interface.
 *
 * Features:
 * - Staggered page load reveals
 * - Ripple effects on buttons
 * - Card hover animations
 * - Scroll-triggered animations
 * - Counter animations
 * - Toast notifications
 * - Loading states
 *
 * Design Philosophy: Motion should feel intentional, not decorative.
 * Every animation serves a purpose: guiding attention, providing feedback,
 * or creating delight.
 *
 * WCAG 2.1 AA Compliant - Respects prefers-reduced-motion
 */

(function() {
    'use strict';

    // Check for reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Animation timing constants
    const TIMING = {
        fast: 150,
        normal: 200,
        slow: 300,
        slower: 500,
        ripple: 600
    };

    /* ==========================================================================
       PAGE LOAD ANIMATION ORCHESTRATOR
       ========================================================================== */

    class PageLoadAnimator {
        constructor() {
            this.elements = [];
            this.baseDelay = 50;
            this.hasAnimated = false;
        }

        init() {
            if (prefersReducedMotion) {
                document.querySelectorAll('[data-animate]').forEach(el => {
                    el.style.opacity = '1';
                    el.style.transform = 'none';
                });
                return;
            }

            this.elements = Array.from(document.querySelectorAll('[data-animate]'));

            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.animate());
            } else {
                requestAnimationFrame(() => {
                    requestAnimationFrame(() => this.animate());
                });
            }
        }

        animate() {
            if (this.hasAnimated) return;
            this.hasAnimated = true;

            const groups = this.groupElements();

            let currentDelay = 0;
            groups.forEach((group) => {
                group.forEach((el, elIndex) => {
                    const delay = currentDelay + (elIndex * this.baseDelay);
                    el.style.animationDelay = `${delay}ms`;
                    el.classList.add('animate-in');
                });
                currentDelay += (group.length * this.baseDelay) + 100;
            });
        }

        groupElements() {
            const grouped = new Map();
            let ungrouped = [];

            this.elements.forEach(el => {
                const group = el.dataset.animateGroup;
                if (group) {
                    if (!grouped.has(group)) {
                        grouped.set(group, []);
                    }
                    grouped.get(group).push(el);
                } else {
                    ungrouped.push(el);
                }
            });

            const result = [];
            grouped.forEach(group => result.push(group));
            if (ungrouped.length > 0) {
                result.push(ungrouped);
            }

            return result;
        }
    }

    /* ==========================================================================
       RIPPLE EFFECT
       ========================================================================== */

    const RippleEffect = {
        init(selector = '.btn, .ripple, [data-ripple]') {
            const elements = typeof selector === 'string'
                ? document.querySelectorAll(selector)
                : (selector instanceof NodeList ? selector : [selector]);

            elements.forEach(el => this.attach(el));

            // Also use event delegation for dynamically added buttons
            document.addEventListener('mousedown', (e) => {
                const target = e.target.closest('.btn, .btn-ripple, [data-ripple]');
                if (target && !target.dataset.rippleAttached) {
                    this.attach(target);
                    this.create(e, target);
                }
            });
        },

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

        create(event, container) {
            if (prefersReducedMotion) {
                container.style.opacity = '0.8';
                setTimeout(() => {
                    container.style.opacity = '';
                }, 150);
                return;
            }

            // Remove existing ripples
            const existingRipple = container.querySelector('.ripple-effect');
            if (existingRipple) existingRipple.remove();

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
                opacity: 0.25;
                border-radius: 50%;
                transform: scale(0);
                pointer-events: none;
                animation: ripple-expand ${TIMING.ripple}ms ease-out forwards;
            `;

            container.appendChild(ripple);

            setTimeout(() => {
                ripple.remove();
            }, TIMING.ripple);
        }
    };

    /* ==========================================================================
       CARD HOVER LIFT EFFECT
       ========================================================================== */

    const CardLift = {
        init(selector = '.card, .card-lift, .card-hover, .hover-lift, [data-lift], [data-hover="lift"]') {
            const cards = document.querySelectorAll(selector);
            cards.forEach(card => this.attach(card));
        },

        attach(card) {
            if (!card || card.dataset.liftAttached) return;

            card.dataset.liftAttached = 'true';

            const originalTransform = card.style.transform || 'translateY(0)';
            const originalShadow = card.style.boxShadow || 'var(--shadow-sm)';

            const duration = prefersReducedMotion ? 0 : TIMING.slow;
            card.style.transition = `transform ${duration}ms cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow ${duration}ms ease`;

            card.addEventListener('mouseenter', () => {
                if (!prefersReducedMotion) {
                    card.style.transform = 'translateY(-4px)';
                    card.style.boxShadow = 'var(--shadow-xl)';
                }
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = originalTransform;
                card.style.boxShadow = originalShadow;
            });

            card.addEventListener('focusin', () => {
                if (!prefersReducedMotion) {
                    card.style.transform = 'translateY(-4px)';
                    card.style.boxShadow = 'var(--shadow-xl)';
                }
            });

            card.addEventListener('focusout', () => {
                card.style.transform = originalTransform;
                card.style.boxShadow = originalShadow;
            });
        }
    };

    /* ==========================================================================
       SCROLL-TRIGGERED ANIMATIONS
       ========================================================================== */

    class ScrollAnimator {
        constructor() {
            this.observer = null;
        }

        init() {
            if (prefersReducedMotion) {
                document.querySelectorAll('[data-scroll-animate]').forEach(el => {
                    el.classList.add('in-view');
                    el.style.opacity = '1';
                    el.style.transform = 'none';
                });
                return;
            }

            const elements = document.querySelectorAll('[data-scroll-animate]');
            if (elements.length === 0) return;

            this.observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const siblings = entry.target.parentElement.querySelectorAll('[data-scroll-animate]');
                        const index = Array.from(siblings).indexOf(entry.target);
                        entry.target.style.transitionDelay = `${index * 50}ms`;

                        entry.target.classList.add('in-view');

                        if (!entry.target.dataset.scrollRepeat) {
                            this.observer.unobserve(entry.target);
                        }
                    } else if (entry.target.dataset.scrollRepeat) {
                        entry.target.classList.remove('in-view');
                    }
                });
            }, {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            });

            elements.forEach(el => this.observer.observe(el));
        }

        destroy() {
            if (this.observer) {
                this.observer.disconnect();
            }
        }
    }

    /* ==========================================================================
       COUNTER ANIMATION
       ========================================================================== */

    class CounterAnimator {
        constructor() {
            this.observer = null;
        }

        init() {
            const counters = document.querySelectorAll('[data-counter], .counter-animate');
            if (counters.length === 0) return;

            this.observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        this.animateCounter(entry.target);
                        this.observer.unobserve(entry.target);
                    }
                });
            }, {
                threshold: 0.5
            });

            counters.forEach(counter => this.observer.observe(counter));
        }

        animateCounter(element) {
            const target = parseFloat(element.dataset.counter || element.textContent.replace(/[^0-9.-]/g, ''));
            const duration = parseInt(element.dataset.counterDuration) || 1500;
            const decimals = (element.dataset.counterDecimals !== undefined)
                ? parseInt(element.dataset.counterDecimals)
                : (target % 1 !== 0 ? 2 : 0);
            const prefix = element.dataset.counterPrefix || '';
            const suffix = element.dataset.counterSuffix || '';

            if (prefersReducedMotion) {
                element.textContent = prefix + this.formatNumber(target, decimals) + suffix;
                return;
            }

            const startTime = performance.now();
            const startValue = 0;

            const animate = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);

                // Ease out cubic
                const easeProgress = 1 - Math.pow(1 - progress, 3);
                const currentValue = startValue + (target - startValue) * easeProgress;

                element.textContent = prefix + this.formatNumber(currentValue, decimals) + suffix;

                if (progress < 1) {
                    requestAnimationFrame(animate);
                }
            };

            requestAnimationFrame(animate);
        }

        formatNumber(value, decimals) {
            return value.toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        }
    }

    /* ==========================================================================
       SUCCESS ANIMATION
       ========================================================================== */

    const SuccessAnimation = {
        show(container, options = {}) {
            return new Promise((resolve) => {
                const {
                    size = 48,
                    color = 'var(--success, #10B981)',
                    duration = prefersReducedMotion ? 0 : 600,
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

                if (!prefersReducedMotion) {
                    svg.style.cssText = `
                        animation: success-scale ${duration}ms ease forwards;
                    `;
                }

                container.appendChild(svg);

                setTimeout(() => {
                    if (autoRemove) {
                        svg.style.opacity = '0';
                        svg.style.transition = 'opacity 0.3s';
                        setTimeout(() => svg.remove(), TIMING.slow);
                    }
                    resolve(svg);
                }, duration + removeDelay);
            });
        }
    };

    /* ==========================================================================
       ERROR SHAKE ANIMATION
       ========================================================================== */

    const ErrorShake = {
        shake(element, options = {}) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                const {
                    intensity = 10,
                    duration = prefersReducedMotion ? 0 : 400
                } = options;

                if (prefersReducedMotion) {
                    element.style.outline = '2px solid var(--danger, #EF4444)';
                    setTimeout(() => {
                        element.style.outline = '';
                        resolve();
                    }, 500);
                    return;
                }

                element.classList.add('is-shaking');
                element.style.animation = `shake ${duration}ms ease`;
                element.style.setProperty('--shake-intensity', `${intensity}px`);

                setTimeout(() => {
                    element.style.animation = '';
                    element.classList.remove('is-shaking');
                    resolve();
                }, duration);
            });
        },

        shakeField(field, message = '') {
            this.shake(field);

            field.classList.add('is-invalid');
            field.setAttribute('aria-invalid', 'true');

            if (message) {
                let errorEl = field.parentNode.querySelector('.error-message');
                if (!errorEl) {
                    errorEl = document.createElement('div');
                    errorEl.className = 'error-message';
                    errorEl.id = `${field.id || 'field'}-error`;
                    errorEl.setAttribute('role', 'alert');
                    errorEl.style.cssText = 'color: var(--danger); font-size: 0.875rem; margin-top: 0.25rem;';
                    field.parentNode.appendChild(errorEl);
                    field.setAttribute('aria-describedby', errorEl.id);
                }
                errorEl.textContent = message;
            }
        }
    };

    /* ==========================================================================
       TOAST NOTIFICATIONS
       ========================================================================== */

    const Toast = {
        container: null,

        init() {
            if (this.container) return;

            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.setAttribute('role', 'region');
            this.container.setAttribute('aria-label', 'Notifications');
            this.container.setAttribute('aria-live', 'polite');
            this.container.style.cssText = `
                position: fixed;
                bottom: 1rem;
                right: 1rem;
                z-index: 10080;
                display: flex;
                flex-direction: column-reverse;
                gap: 0.5rem;
                max-height: 100vh;
                overflow: hidden;
                pointer-events: none;
            `;

            document.body.appendChild(this.container);

            // Listen for custom toast events
            window.addEventListener('toast', (e) => this.show(e.detail));
            window.addEventListener('zumodra:toast', (e) => this.show(e.detail));
        },

        show(options = {}) {
            this.init();

            const {
                message = '',
                type = 'info',
                duration = 5000,
                dismissible = true,
                icon = null,
                action = null,
                actionText = 'Undo'
            } = options;

            const toast = document.createElement('div');
            toast.className = `toast toast--${type}`;
            toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
            toast.setAttribute('aria-atomic', 'true');

            const icons = {
                info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
                success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
                warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'
            };

            const colorClasses = {
                info: 'color: var(--info);',
                success: 'color: var(--success);',
                warning: 'color: var(--warning);',
                error: 'color: var(--danger);'
            };

            const transitionDuration = prefersReducedMotion ? 0 : TIMING.slow;

            toast.style.cssText = `
                display: flex;
                align-items: flex-start;
                gap: 0.75rem;
                padding: 1rem 1.25rem;
                min-width: 320px;
                max-width: 420px;
                background: var(--card-bg);
                border: 1px solid var(--border-primary);
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow-lg);
                pointer-events: auto;
                transform: translateX(120%);
                opacity: 0;
                transition: transform ${transitionDuration}ms cubic-bezier(0.34, 1.56, 0.64, 1),
                            opacity ${transitionDuration}ms ease;
            `;

            toast.innerHTML = `
                <span style="${colorClasses[type] || colorClasses.info} flex-shrink: 0;">${icon || icons[type]}</span>
                <div style="flex: 1;">
                    <p style="margin: 0; font-size: 0.875rem; color: var(--text-primary); line-height: 1.5;">${message}</p>
                    ${action ? `<button class="toast__action" style="margin-top: 0.5rem; padding: 0.25rem 0.5rem; background: transparent; border: 1px solid var(--accent-coral); border-radius: var(--radius-sm); color: var(--accent-coral); cursor: pointer; font-size: 0.75rem; font-weight: 500;">${actionText}</button>` : ''}
                </div>
                ${dismissible ? `<button class="toast__dismiss" aria-label="Dismiss notification" style="flex-shrink: 0; background: none; border: none; padding: 0.25rem; cursor: pointer; color: var(--text-tertiary); transition: color 0.15s;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : ''}
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
                dismissBtn.addEventListener('mouseenter', () => dismissBtn.style.color = 'var(--text-primary)');
                dismissBtn.addEventListener('mouseleave', () => dismissBtn.style.color = 'var(--text-tertiary)');
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

        dismiss(toast) {
            if (!toast || toast.classList.contains('is-dismissing')) return;

            toast.classList.add('is-dismissing');
            toast.style.transform = 'translateX(120%)';
            toast.style.opacity = '0';

            setTimeout(() => {
                toast.remove();
            }, prefersReducedMotion ? 0 : TIMING.slow);
        },

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

    /* ==========================================================================
       FADE & SLIDE TRANSITIONS
       ========================================================================== */

    const Fade = {
        in(element, duration = TIMING.slow) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = prefersReducedMotion ? 0 : duration;
                element.style.opacity = '0';
                element.style.display = '';
                element.style.transition = `opacity ${duration}ms ease`;

                requestAnimationFrame(() => {
                    element.style.opacity = '1';
                    setTimeout(resolve, duration);
                });
            });
        },

        out(element, duration = TIMING.slow, hide = true) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = prefersReducedMotion ? 0 : duration;
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

    const Slide = {
        down(element, duration = TIMING.slow) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = prefersReducedMotion ? 0 : duration;

                element.style.display = '';
                element.style.height = 'auto';
                element.style.overflow = 'hidden';
                const height = element.offsetHeight;

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

        up(element, duration = TIMING.slow) {
            return new Promise((resolve) => {
                if (!element) {
                    resolve();
                    return;
                }

                duration = prefersReducedMotion ? 0 : duration;

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

        toggle(element, duration = TIMING.slow) {
            if (!element) return Promise.resolve();

            const isHidden = element.offsetHeight === 0 ||
                           getComputedStyle(element).display === 'none';

            return isHidden ? this.down(element, duration) : this.up(element, duration);
        }
    };

    /* ==========================================================================
       SKELETON LOADER
       ========================================================================== */

    const SkeletonLoader = {
        create(type = 'text', options = {}) {
            const skeleton = document.createElement('div');
            skeleton.className = 'skeleton';
            skeleton.setAttribute('aria-hidden', 'true');

            const baseStyle = `
                background: linear-gradient(90deg, var(--bg-tertiary) 25%, var(--bg-secondary) 50%, var(--bg-tertiary) 75%);
                background-size: 200% 100%;
                animation: shimmer 1.5s infinite;
                border-radius: var(--radius-md);
            `;

            switch (type) {
                case 'text':
                    skeleton.style.cssText = baseStyle + `height: 1em; width: ${options.width || '100%'};`;
                    break;
                case 'title':
                    skeleton.style.cssText = baseStyle + 'height: 1.5em; width: 60%;';
                    break;
                case 'avatar':
                    const size = options.size || '48px';
                    skeleton.style.cssText = baseStyle + `width: ${size}; height: ${size}; border-radius: 50%;`;
                    break;
                case 'card':
                    skeleton.style.cssText = baseStyle + `height: ${options.height || '200px'}; border-radius: var(--radius-lg);`;
                    break;
                case 'button':
                    skeleton.style.cssText = baseStyle + 'height: 40px; width: 120px;';
                    break;
            }

            return skeleton;
        }
    };

    /* ==========================================================================
       BUTTON LOADING STATE
       ========================================================================== */

    const ButtonLoading = {
        start(button) {
            if (button.classList.contains('btn-loading')) return;

            button.dataset.originalContent = button.innerHTML;
            button.dataset.originalWidth = button.offsetWidth + 'px';

            button.style.width = button.dataset.originalWidth;
            button.classList.add('btn-loading');
            button.disabled = true;
        },

        stop(button) {
            if (!button.classList.contains('btn-loading')) return;

            button.classList.remove('btn-loading');
            button.disabled = false;
            button.style.width = '';

            if (button.dataset.originalContent) {
                button.innerHTML = button.dataset.originalContent;
                delete button.dataset.originalContent;
                delete button.dataset.originalWidth;
            }
        }
    };

    /* ==========================================================================
       HTMX INTEGRATION
       ========================================================================== */

    const HtmxAnimations = {
        init() {
            document.body.addEventListener('htmx:beforeSwap', (e) => {
                const target = e.detail.target;
                if (target) {
                    target.classList.add('htmx-swapping');
                }
            });

            document.body.addEventListener('htmx:afterSwap', (e) => {
                const target = e.detail.target;
                if (target) {
                    target.classList.remove('htmx-swapping');
                    target.classList.add('htmx-settling');

                    this.initializeNewContent(target);

                    setTimeout(() => {
                        target.classList.remove('htmx-settling');
                    }, 200);
                }
            });

            document.body.addEventListener('htmx:afterSettle', () => {
                if (window.ZumodraAnimations && window.ZumodraAnimations.scrollAnimator) {
                    window.ZumodraAnimations.scrollAnimator.init();
                }
            });
        },

        initializeNewContent(container) {
            const animateElements = container.querySelectorAll('[data-animate]');
            animateElements.forEach((el, index) => {
                el.style.animationDelay = `${index * 50}ms`;
                el.classList.add('animate-in');
            });

            if (window.ZumodraAnimations && window.ZumodraAnimations.counterAnimator) {
                window.ZumodraAnimations.counterAnimator.init();
            }
        }
    };

    /* ==========================================================================
       INJECT REQUIRED CSS
       ========================================================================== */

    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple-expand {
            to {
                transform: scale(1);
                opacity: 0;
            }
        }

        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }

        @keyframes success-scale {
            0% { transform: scale(0); opacity: 0; }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); opacity: 1; }
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

        .btn-loading {
            color: transparent !important;
            pointer-events: none;
            position: relative;
        }

        .btn-loading::after {
            content: '';
            position: absolute;
            width: 1rem;
            height: 1rem;
            top: 50%;
            left: 50%;
            margin: -0.5rem 0 0 -0.5rem;
            border: 2px solid currentColor;
            border-right-color: transparent;
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .htmx-swapping {
            opacity: 0.5;
            transition: opacity 0.15s ease;
        }

        .htmx-settling {
            animation: fadeIn 0.2s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes scaleIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }

        [data-animate] {
            opacity: 0;
        }

        [data-animate].animate-in {
            animation-fill-mode: both;
            animation-timing-function: cubic-bezier(0.16, 1, 0.3, 1);
        }

        [data-animate="fade"].animate-in { animation: fadeIn 0.5s ease-out; }
        [data-animate="fade-up"].animate-in { animation: fadeInUp 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
        [data-animate="fade-down"].animate-in { animation: fadeInDown 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
        [data-animate="scale"].animate-in { animation: scaleIn 0.5s cubic-bezier(0.16, 1, 0.3, 1); }

        [data-scroll-animate] {
            opacity: 0;
            transform: translateY(30px);
            transition: opacity 0.6s ease-out, transform 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        [data-scroll-animate].in-view {
            opacity: 1;
            transform: translateY(0);
        }

        /* Dark mode toast adjustments */
        [data-theme="dark"] .toast--info,
        .dark .toast--info {
            background: var(--info-light);
            border-color: var(--info);
        }

        [data-theme="dark"] .toast--success,
        .dark .toast--success {
            background: var(--success-light);
            border-color: var(--success);
        }

        [data-theme="dark"] .toast--warning,
        .dark .toast--warning {
            background: var(--warning-light);
            border-color: var(--warning);
        }

        [data-theme="dark"] .toast--error,
        .dark .toast--error {
            background: var(--danger-light);
            border-color: var(--danger);
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }

            [data-animate], [data-scroll-animate] {
                opacity: 1 !important;
                transform: none !important;
            }

            .ripple-effect,
            .success-checkmark,
            .success-checkmark__circle,
            .success-checkmark__check {
                animation: none !important;
            }

            .success-checkmark__circle,
            .success-checkmark__check {
                stroke-dashoffset: 0;
            }

            .toast {
                transform: none !important;
            }
        }
    `;
    document.head.appendChild(style);

    /* ==========================================================================
       GLOBAL API
       ========================================================================== */

    // Instances
    let pageLoadAnimator = null;
    let scrollAnimator = null;
    let counterAnimator = null;

    window.ZumodraAnimations = {
        get pageLoadAnimator() { return pageLoadAnimator; },
        get scrollAnimator() { return scrollAnimator; },
        get counterAnimator() { return counterAnimator; },

        init() {
            pageLoadAnimator = new PageLoadAnimator();
            scrollAnimator = new ScrollAnimator();
            counterAnimator = new CounterAnimator();

            pageLoadAnimator.init();
            RippleEffect.init();
            CardLift.init();
            scrollAnimator.init();
            counterAnimator.init();
            Toast.init();
            HtmxAnimations.init();
        },

        // Public API
        toast(options) {
            return Toast.show(options);
        },

        successAnimation(element, options) {
            return SuccessAnimation.show(element, options);
        },

        shake(element, options) {
            return ErrorShake.shake(element, options);
        },

        skeleton(type, options) {
            return SkeletonLoader.create(type, options);
        },

        buttonLoading: ButtonLoading,

        fade: Fade,
        slide: Slide,

        animate(element, animation, duration = 300) {
            if (prefersReducedMotion) {
                element.classList.add('animate-in');
                return Promise.resolve();
            }

            return new Promise(resolve => {
                element.style.animationDuration = `${duration}ms`;
                element.classList.add('animate', `animate-${animation}`);

                element.addEventListener('animationend', () => {
                    element.classList.remove('animate', `animate-${animation}`);
                    resolve();
                }, { once: true });
            });
        },

        prefersReducedMotion() {
            return prefersReducedMotion;
        }
    };

    // Legacy API compatibility
    window.ZumodraMicro = {
        Ripple: RippleEffect,
        CardLift,
        Success: SuccessAnimation,
        ErrorShake,
        Toast,
        Fade,
        Slide,
        getAnimationDuration: (d) => prefersReducedMotion ? 0 : d,
        prefersReducedMotion: () => prefersReducedMotion
    };

    // Auto-initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.ZumodraAnimations.init();
        });
    } else {
        window.ZumodraAnimations.init();
    }

    // Dispatch ready event
    window.dispatchEvent(new CustomEvent('zumodra:micro-ready'));
    window.dispatchEvent(new CustomEvent('zumodra:animations-ready'));

})();
