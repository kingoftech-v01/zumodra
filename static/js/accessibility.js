/**
 * Accessibility Helpers for Zumodra
 *
 * Features:
 * - Focus trap for modals and dialogs
 * - Skip to content link handler
 * - Keyboard navigation helpers
 * - ARIA live region announcer
 * - Reduced motion detection
 * - Roving tabindex for complex widgets
 *
 * WCAG 2.1 AA Compliant
 */

(function() {
    'use strict';

    // Constants
    const FOCUSABLE_SELECTORS = [
        'a[href]',
        'button:not([disabled])',
        'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
        '[contenteditable="true"]',
        'audio[controls]',
        'video[controls]',
        'details > summary:first-of-type',
        'iframe'
    ].join(', ');

    const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

    /**
     * Focus Trap Manager
     * Traps focus within a container (e.g., modals, dialogs)
     */
    class FocusTrap {
        constructor(container, options = {}) {
            this.container = typeof container === 'string'
                ? document.querySelector(container)
                : container;

            this.options = {
                initialFocus: options.initialFocus || null,
                returnFocus: options.returnFocus !== false,
                escapeDeactivates: options.escapeDeactivates !== false,
                clickOutsideDeactivates: options.clickOutsideDeactivates || false,
                onActivate: options.onActivate || null,
                onDeactivate: options.onDeactivate || null
            };

            this.active = false;
            this.previousActiveElement = null;
            this.firstFocusable = null;
            this.lastFocusable = null;

            this.handleKeyDown = this.handleKeyDown.bind(this);
            this.handleClickOutside = this.handleClickOutside.bind(this);
        }

        /**
         * Get all focusable elements within the container
         * @returns {NodeList} Focusable elements
         */
        getFocusableElements() {
            return this.container.querySelectorAll(FOCUSABLE_SELECTORS);
        }

        /**
         * Update references to first and last focusable elements
         */
        updateFocusableElements() {
            const focusables = Array.from(this.getFocusableElements()).filter(el => {
                return el.offsetParent !== null && !el.hasAttribute('inert');
            });

            this.firstFocusable = focusables[0] || null;
            this.lastFocusable = focusables[focusables.length - 1] || null;
        }

        /**
         * Activate the focus trap
         */
        activate() {
            if (this.active || !this.container) return;

            this.active = true;
            this.previousActiveElement = document.activeElement;
            this.updateFocusableElements();

            // Set initial focus
            requestAnimationFrame(() => {
                let focusTarget = null;

                if (this.options.initialFocus) {
                    focusTarget = typeof this.options.initialFocus === 'string'
                        ? this.container.querySelector(this.options.initialFocus)
                        : this.options.initialFocus;
                }

                if (!focusTarget) {
                    focusTarget = this.firstFocusable || this.container;
                }

                if (focusTarget && typeof focusTarget.focus === 'function') {
                    focusTarget.focus();
                }
            });

            // Add event listeners
            document.addEventListener('keydown', this.handleKeyDown);

            if (this.options.clickOutsideDeactivates) {
                document.addEventListener('click', this.handleClickOutside, true);
            }

            // Mark container as modal
            this.container.setAttribute('aria-modal', 'true');

            // Callback
            if (this.options.onActivate) {
                this.options.onActivate(this);
            }
        }

        /**
         * Deactivate the focus trap
         */
        deactivate() {
            if (!this.active) return;

            this.active = false;

            // Remove event listeners
            document.removeEventListener('keydown', this.handleKeyDown);
            document.removeEventListener('click', this.handleClickOutside, true);

            // Remove modal attribute
            this.container.removeAttribute('aria-modal');

            // Return focus to previous element
            if (this.options.returnFocus && this.previousActiveElement) {
                requestAnimationFrame(() => {
                    if (typeof this.previousActiveElement.focus === 'function') {
                        this.previousActiveElement.focus();
                    }
                });
            }

            // Callback
            if (this.options.onDeactivate) {
                this.options.onDeactivate(this);
            }
        }

        /**
         * Handle keydown events
         * @param {KeyboardEvent} event
         */
        handleKeyDown(event) {
            if (!this.active) return;

            // Escape key
            if (event.key === 'Escape' && this.options.escapeDeactivates) {
                event.preventDefault();
                event.stopPropagation();
                this.deactivate();
                return;
            }

            // Tab key - trap focus
            if (event.key === 'Tab') {
                this.updateFocusableElements();

                if (!this.firstFocusable) {
                    event.preventDefault();
                    return;
                }

                if (event.shiftKey) {
                    // Shift + Tab
                    if (document.activeElement === this.firstFocusable) {
                        event.preventDefault();
                        this.lastFocusable.focus();
                    }
                } else {
                    // Tab
                    if (document.activeElement === this.lastFocusable) {
                        event.preventDefault();
                        this.firstFocusable.focus();
                    }
                }
            }
        }

        /**
         * Handle clicks outside the container
         * @param {MouseEvent} event
         */
        handleClickOutside(event) {
            if (this.active && !this.container.contains(event.target)) {
                this.deactivate();
            }
        }

        /**
         * Toggle the focus trap
         */
        toggle() {
            if (this.active) {
                this.deactivate();
            } else {
                this.activate();
            }
        }

        /**
         * Check if trap is active
         * @returns {boolean}
         */
        isActive() {
            return this.active;
        }
    }

    /**
     * Skip Link Handler
     * Manages skip to content functionality
     */
    class SkipLinkHandler {
        constructor() {
            this.init();
        }

        /**
         * Initialize skip link functionality
         */
        init() {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.setup());
            } else {
                this.setup();
            }
        }

        /**
         * Set up skip link event listeners
         */
        setup() {
            const skipLinks = document.querySelectorAll('.skip-link, [data-skip-link]');

            skipLinks.forEach(link => {
                link.addEventListener('click', this.handleClick.bind(this));
                link.addEventListener('keydown', this.handleKeyDown.bind(this));
            });
        }

        /**
         * Handle skip link click
         * @param {Event} event
         */
        handleClick(event) {
            const targetId = event.target.getAttribute('href');

            if (!targetId || !targetId.startsWith('#')) return;

            const target = document.querySelector(targetId);

            if (target) {
                event.preventDefault();

                // Make target focusable if it isn't already
                if (!target.hasAttribute('tabindex')) {
                    target.setAttribute('tabindex', '-1');
                }

                // Scroll to target
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });

                // Focus target
                requestAnimationFrame(() => {
                    target.focus();

                    // Announce for screen readers
                    Announcer.announce('Skipped to main content');
                });
            }
        }

        /**
         * Handle keydown on skip link
         * @param {KeyboardEvent} event
         */
        handleKeyDown(event) {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                this.handleClick(event);
            }
        }
    }

    /**
     * Keyboard Navigation Helpers
     * Provides utilities for keyboard navigation patterns
     */
    class KeyboardNavigation {
        /**
         * Handle arrow key navigation within a container
         * @param {HTMLElement} container - Container element
         * @param {Object} options - Navigation options
         */
        static setupArrowNavigation(container, options = {}) {
            const {
                selector = '[role="menuitem"], [role="option"], [role="tab"]',
                orientation = 'vertical', // 'vertical', 'horizontal', or 'both'
                wrap = true,
                onSelect = null
            } = options;

            container.addEventListener('keydown', (event) => {
                const items = Array.from(container.querySelectorAll(selector));
                const currentIndex = items.indexOf(document.activeElement);

                if (currentIndex === -1) return;

                let nextIndex = currentIndex;
                let handled = false;

                switch (event.key) {
                    case 'ArrowUp':
                        if (orientation === 'vertical' || orientation === 'both') {
                            nextIndex = currentIndex - 1;
                            handled = true;
                        }
                        break;
                    case 'ArrowDown':
                        if (orientation === 'vertical' || orientation === 'both') {
                            nextIndex = currentIndex + 1;
                            handled = true;
                        }
                        break;
                    case 'ArrowLeft':
                        if (orientation === 'horizontal' || orientation === 'both') {
                            nextIndex = currentIndex - 1;
                            handled = true;
                        }
                        break;
                    case 'ArrowRight':
                        if (orientation === 'horizontal' || orientation === 'both') {
                            nextIndex = currentIndex + 1;
                            handled = true;
                        }
                        break;
                    case 'Home':
                        nextIndex = 0;
                        handled = true;
                        break;
                    case 'End':
                        nextIndex = items.length - 1;
                        handled = true;
                        break;
                    case 'Enter':
                    case ' ':
                        if (onSelect) {
                            event.preventDefault();
                            onSelect(items[currentIndex], currentIndex);
                        }
                        return;
                }

                if (handled) {
                    event.preventDefault();

                    // Handle wrapping
                    if (wrap) {
                        if (nextIndex < 0) nextIndex = items.length - 1;
                        if (nextIndex >= items.length) nextIndex = 0;
                    } else {
                        nextIndex = Math.max(0, Math.min(items.length - 1, nextIndex));
                    }

                    if (items[nextIndex]) {
                        items[nextIndex].focus();
                    }
                }
            });
        }

        /**
         * Set up roving tabindex pattern
         * @param {HTMLElement} container - Container element
         * @param {string} itemSelector - Selector for items
         */
        static setupRovingTabindex(container, itemSelector) {
            const items = container.querySelectorAll(itemSelector);

            // Initialize tabindex
            items.forEach((item, index) => {
                item.setAttribute('tabindex', index === 0 ? '0' : '-1');
            });

            container.addEventListener('keydown', (event) => {
                const currentItem = document.activeElement;
                const itemsArray = Array.from(items);
                const currentIndex = itemsArray.indexOf(currentItem);

                if (currentIndex === -1) return;

                let nextIndex = -1;

                if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
                    nextIndex = (currentIndex + 1) % itemsArray.length;
                } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
                    nextIndex = (currentIndex - 1 + itemsArray.length) % itemsArray.length;
                } else if (event.key === 'Home') {
                    nextIndex = 0;
                } else if (event.key === 'End') {
                    nextIndex = itemsArray.length - 1;
                }

                if (nextIndex !== -1) {
                    event.preventDefault();

                    // Update tabindex
                    itemsArray.forEach((item, index) => {
                        item.setAttribute('tabindex', index === nextIndex ? '0' : '-1');
                    });

                    itemsArray[nextIndex].focus();
                }
            });
        }
    }

    /**
     * ARIA Live Region Announcer
     * Provides screen reader announcements
     */
    const Announcer = {
        /** @type {HTMLElement|null} */
        politeRegion: null,
        /** @type {HTMLElement|null} */
        assertiveRegion: null,

        /**
         * Initialize the announcer regions
         */
        init() {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.createRegions());
            } else {
                this.createRegions();
            }
        },

        /**
         * Create ARIA live regions
         */
        createRegions() {
            // Polite region (for non-urgent announcements)
            if (!document.getElementById('aria-live-polite')) {
                this.politeRegion = document.createElement('div');
                this.politeRegion.id = 'aria-live-polite';
                this.politeRegion.setAttribute('role', 'status');
                this.politeRegion.setAttribute('aria-live', 'polite');
                this.politeRegion.setAttribute('aria-atomic', 'true');
                this.politeRegion.className = 'sr-only';
                document.body.appendChild(this.politeRegion);
            } else {
                this.politeRegion = document.getElementById('aria-live-polite');
            }

            // Assertive region (for urgent announcements)
            if (!document.getElementById('aria-live-assertive')) {
                this.assertiveRegion = document.createElement('div');
                this.assertiveRegion.id = 'aria-live-assertive';
                this.assertiveRegion.setAttribute('role', 'alert');
                this.assertiveRegion.setAttribute('aria-live', 'assertive');
                this.assertiveRegion.setAttribute('aria-atomic', 'true');
                this.assertiveRegion.className = 'sr-only';
                document.body.appendChild(this.assertiveRegion);
            } else {
                this.assertiveRegion = document.getElementById('aria-live-assertive');
            }
        },

        /**
         * Announce a message to screen readers
         * @param {string} message - Message to announce
         * @param {string} priority - 'polite' or 'assertive'
         * @param {number} clearDelay - Delay before clearing (ms)
         */
        announce(message, priority = 'polite', clearDelay = 5000) {
            if (!this.politeRegion || !this.assertiveRegion) {
                this.createRegions();
            }

            const region = priority === 'assertive' ? this.assertiveRegion : this.politeRegion;

            if (!region) return;

            // Clear and re-set for consistent announcement
            region.textContent = '';

            // Use setTimeout to ensure the empty state is registered
            requestAnimationFrame(() => {
                region.textContent = message;

                // Clear after delay
                if (clearDelay > 0) {
                    setTimeout(() => {
                        region.textContent = '';
                    }, clearDelay);
                }
            });
        },

        /**
         * Announce polite message (non-interruptive)
         * @param {string} message - Message to announce
         */
        polite(message) {
            this.announce(message, 'polite');
        },

        /**
         * Announce assertive message (interruptive)
         * @param {string} message - Message to announce
         */
        assertive(message) {
            this.announce(message, 'assertive');
        }
    };

    /**
     * Reduced Motion Detection
     * Detects and responds to user preference for reduced motion
     */
    const ReducedMotion = {
        /** @type {MediaQueryList|null} */
        mediaQuery: null,
        /** @type {Set<Function>} */
        listeners: new Set(),

        /**
         * Initialize reduced motion detection
         */
        init() {
            if (!window.matchMedia) return;

            this.mediaQuery = window.matchMedia(REDUCED_MOTION_QUERY);

            // Set up listener for changes
            const handleChange = (event) => {
                this.notifyListeners(event.matches);

                // Update CSS custom property
                document.documentElement.style.setProperty(
                    '--reduce-motion',
                    event.matches ? '1' : '0'
                );
            };

            if (this.mediaQuery.addEventListener) {
                this.mediaQuery.addEventListener('change', handleChange);
            } else {
                this.mediaQuery.addListener(handleChange);
            }

            // Initial state
            handleChange({ matches: this.mediaQuery.matches });
        },

        /**
         * Check if reduced motion is preferred
         * @returns {boolean} True if reduced motion is preferred
         */
        isReduced() {
            return this.mediaQuery ? this.mediaQuery.matches : false;
        },

        /**
         * Get appropriate duration based on user preference
         * @param {number} normalDuration - Normal animation duration (ms)
         * @param {number} reducedDuration - Reduced motion duration (ms)
         * @returns {number} Appropriate duration
         */
        getDuration(normalDuration, reducedDuration = 0) {
            return this.isReduced() ? reducedDuration : normalDuration;
        },

        /**
         * Add listener for reduced motion changes
         * @param {Function} callback - Callback function
         */
        onChange(callback) {
            if (typeof callback === 'function') {
                this.listeners.add(callback);
            }
        },

        /**
         * Remove listener
         * @param {Function} callback - Callback to remove
         */
        offChange(callback) {
            this.listeners.delete(callback);
        },

        /**
         * Notify listeners of changes
         * @param {boolean} isReduced - Current state
         */
        notifyListeners(isReduced) {
            this.listeners.forEach(callback => {
                try {
                    callback(isReduced);
                } catch (e) {
                    console.error('Reduced motion listener error:', e);
                }
            });
        }
    };

    /**
     * Focus Management Utilities
     */
    const FocusManager = {
        /**
         * Store current focus for later restoration
         * @returns {HTMLElement|null} Currently focused element
         */
        saveFocus() {
            return document.activeElement;
        },

        /**
         * Restore focus to an element
         * @param {HTMLElement} element - Element to focus
         */
        restoreFocus(element) {
            if (element && typeof element.focus === 'function') {
                requestAnimationFrame(() => {
                    element.focus();
                });
            }
        },

        /**
         * Focus first focusable element in container
         * @param {HTMLElement} container - Container element
         * @returns {boolean} True if focus was set
         */
        focusFirst(container) {
            const first = container.querySelector(FOCUSABLE_SELECTORS);
            if (first) {
                first.focus();
                return true;
            }
            return false;
        },

        /**
         * Check if element is focusable
         * @param {HTMLElement} element - Element to check
         * @returns {boolean} True if focusable
         */
        isFocusable(element) {
            if (!element) return false;
            return element.matches(FOCUSABLE_SELECTORS) && element.offsetParent !== null;
        },

        /**
         * Make element programmatically focusable
         * @param {HTMLElement} element - Element to make focusable
         */
        makeFocusable(element) {
            if (!element.hasAttribute('tabindex')) {
                element.setAttribute('tabindex', '-1');
            }
        }
    };

    // Initialize on load
    const skipLinkHandler = new SkipLinkHandler();
    Announcer.init();
    ReducedMotion.init();

    // Expose to global scope
    window.ZumodraA11y = {
        FocusTrap,
        SkipLinkHandler,
        KeyboardNavigation,
        Announcer,
        ReducedMotion,
        FocusManager,
        FOCUSABLE_SELECTORS
    };

    // Dispatch ready event
    window.dispatchEvent(new CustomEvent('zumodra:a11y-ready'));

})();
