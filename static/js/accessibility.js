/**
 * Zumodra Accessibility Module
 *
 * WCAG 2.1 AA compliant accessibility features:
 * - Focus trap for modals
 * - Skip link handling
 * - Keyboard navigation
 * - ARIA live region announcements
 * - Reduced motion support
 */

(function() {
    'use strict';

    /**
     * Focus Trap - Keeps keyboard focus within a container
     */
    class FocusTrap {
        constructor(element) {
            this.element = element;
            this.firstFocusable = null;
            this.lastFocusable = null;
            this.active = false;
            this.handleKeyDown = this.handleKeyDown.bind(this);
        }

        getFocusableElements() {
            const selector = [
                'a[href]',
                'button:not([disabled])',
                'input:not([disabled])',
                'select:not([disabled])',
                'textarea:not([disabled])',
                '[tabindex]:not([tabindex="-1"])',
                '[contenteditable]'
            ].join(',');

            return Array.from(this.element.querySelectorAll(selector))
                .filter(el => !el.closest('[hidden]') && el.offsetParent !== null);
        }

        activate() {
            if (this.active) return;

            const focusable = this.getFocusableElements();
            this.firstFocusable = focusable[0];
            this.lastFocusable = focusable[focusable.length - 1];

            document.addEventListener('keydown', this.handleKeyDown);
            this.active = true;

            // Focus first focusable element
            if (this.firstFocusable) {
                this.firstFocusable.focus();
            }
        }

        deactivate() {
            if (!this.active) return;

            document.removeEventListener('keydown', this.handleKeyDown);
            this.active = false;
        }

        handleKeyDown(e) {
            if (e.key !== 'Tab') return;

            const focusable = this.getFocusableElements();
            this.firstFocusable = focusable[0];
            this.lastFocusable = focusable[focusable.length - 1];

            if (e.shiftKey) {
                if (document.activeElement === this.firstFocusable) {
                    e.preventDefault();
                    this.lastFocusable?.focus();
                }
            } else {
                if (document.activeElement === this.lastFocusable) {
                    e.preventDefault();
                    this.firstFocusable?.focus();
                }
            }
        }
    }

    /**
     * Skip Link Handler - Smooth scrolling to main content
     */
    const SkipLinkHandler = {
        init() {
            document.addEventListener('click', (e) => {
                const skipLink = e.target.closest('.skip-link');
                if (!skipLink) return;

                const targetId = skipLink.getAttribute('href').slice(1);
                const target = document.getElementById(targetId);

                if (target) {
                    e.preventDefault();
                    target.setAttribute('tabindex', '-1');
                    target.focus();
                    target.scrollIntoView({ behavior: this.prefersReducedMotion() ? 'auto' : 'smooth' });
                }
            });
        },

        prefersReducedMotion() {
            return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        }
    };

    /**
     * Keyboard Navigation - Enhanced keyboard support
     */
    const KeyboardNavigation = {
        init() {
            // Show focus styles only for keyboard users
            this.setupFocusVisibility();

            // Arrow key navigation for lists and menus
            this.setupArrowNavigation();

            // Escape key handling
            this.setupEscapeHandler();
        },

        setupFocusVisibility() {
            let hadKeyboardEvent = false;

            document.addEventListener('keydown', () => {
                hadKeyboardEvent = true;
            });

            document.addEventListener('mousedown', () => {
                hadKeyboardEvent = false;
            });

            document.addEventListener('focusin', (e) => {
                if (hadKeyboardEvent) {
                    e.target.classList.add('focus-visible');
                }
            });

            document.addEventListener('focusout', (e) => {
                e.target.classList.remove('focus-visible');
            });
        },

        setupArrowNavigation() {
            document.addEventListener('keydown', (e) => {
                const menu = e.target.closest('[role="menu"], [role="listbox"]');
                if (!menu) return;

                const items = Array.from(menu.querySelectorAll('[role="menuitem"], [role="option"]'));
                const currentIndex = items.indexOf(document.activeElement);

                if (currentIndex === -1) return;

                let nextIndex;

                switch (e.key) {
                    case 'ArrowDown':
                    case 'ArrowRight':
                        e.preventDefault();
                        nextIndex = (currentIndex + 1) % items.length;
                        items[nextIndex].focus();
                        break;

                    case 'ArrowUp':
                    case 'ArrowLeft':
                        e.preventDefault();
                        nextIndex = (currentIndex - 1 + items.length) % items.length;
                        items[nextIndex].focus();
                        break;

                    case 'Home':
                        e.preventDefault();
                        items[0].focus();
                        break;

                    case 'End':
                        e.preventDefault();
                        items[items.length - 1].focus();
                        break;
                }
            });
        },

        setupEscapeHandler() {
            document.addEventListener('keydown', (e) => {
                if (e.key !== 'Escape') return;

                // Close open modals
                const modal = document.querySelector('.modal.show, [role="dialog"][aria-hidden="false"]');
                if (modal) {
                    const closeBtn = modal.querySelector('[data-dismiss="modal"], .modal-close');
                    if (closeBtn) closeBtn.click();
                    return;
                }

                // Close open dropdowns
                const dropdown = document.querySelector('.dropdown.show, [aria-expanded="true"]');
                if (dropdown) {
                    dropdown.click();
                }
            });
        }
    };

    /**
     * ARIA Announcer - Screen reader announcements
     */
    const AriaAnnouncer = {
        liveRegion: null,

        init() {
            this.createLiveRegion();
        },

        createLiveRegion() {
            this.liveRegion = document.getElementById('aria-live-announcer');

            if (!this.liveRegion) {
                this.liveRegion = document.createElement('div');
                this.liveRegion.id = 'aria-live-announcer';
                this.liveRegion.setAttribute('aria-live', 'polite');
                this.liveRegion.setAttribute('aria-atomic', 'true');
                this.liveRegion.classList.add('sr-only');
                document.body.appendChild(this.liveRegion);
            }
        },

        /**
         * Announce a message to screen readers
         * @param {string} message - Message to announce
         * @param {string} priority - 'polite' or 'assertive'
         */
        announce(message, priority = 'polite') {
            if (!this.liveRegion) this.createLiveRegion();

            this.liveRegion.setAttribute('aria-live', priority);

            // Clear and set message (needed for repeated announcements)
            this.liveRegion.textContent = '';

            // Use setTimeout to ensure the DOM change triggers the announcement
            setTimeout(() => {
                this.liveRegion.textContent = message;
            }, 100);
        }
    };

    /**
     * Reduced Motion Handler - Respects user preferences
     */
    const ReducedMotion = {
        mediaQuery: null,

        init() {
            this.mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
            this.applyPreference();

            this.mediaQuery.addEventListener('change', () => this.applyPreference());
        },

        applyPreference() {
            if (this.mediaQuery.matches) {
                document.documentElement.classList.add('reduced-motion');
            } else {
                document.documentElement.classList.remove('reduced-motion');
            }
        },

        prefersReducedMotion() {
            return this.mediaQuery?.matches ?? false;
        }
    };

    /**
     * Form Accessibility - Enhanced form interactions
     */
    const FormAccessibility = {
        init() {
            this.setupErrorAnnouncements();
            this.setupRequiredFieldIndicators();
        },

        setupErrorAnnouncements() {
            // Announce form errors to screen readers
            document.addEventListener('invalid', (e) => {
                const field = e.target;
                const errorMessage = field.validationMessage || 'This field has an error';
                AriaAnnouncer.announce(`Error: ${errorMessage}`, 'assertive');
            }, true);
        },

        setupRequiredFieldIndicators() {
            // Ensure required fields have proper ARIA attributes
            document.querySelectorAll('[required]').forEach(field => {
                if (!field.getAttribute('aria-required')) {
                    field.setAttribute('aria-required', 'true');
                }
            });
        }
    };

    // Initialize all modules when DOM is ready
    function init() {
        SkipLinkHandler.init();
        KeyboardNavigation.init();
        AriaAnnouncer.init();
        ReducedMotion.init();
        FormAccessibility.init();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose utilities globally
    window.ZumodraA11y = {
        FocusTrap,
        announce: AriaAnnouncer.announce.bind(AriaAnnouncer),
        prefersReducedMotion: () => ReducedMotion.prefersReducedMotion()
    };

})();
