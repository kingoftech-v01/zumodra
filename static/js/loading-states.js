/**
 * Zumodra Loading States Module
 *
 * Provides skeleton screens, progress indicators, and loading states:
 * - Skeleton loaders for content
 * - Button loading states
 * - Page transition loading
 * - Async content loading
 */

(function() {
    'use strict';

    /**
     * Skeleton Loader - Creates animated placeholder content
     */
    const SkeletonLoader = {
        /**
         * Create a skeleton element
         * @param {string} type - Type: 'text', 'circle', 'rect', 'card'
         * @param {Object} options - Size options
         * @returns {HTMLElement}
         */
        create(type, options = {}) {
            const skeleton = document.createElement('div');
            skeleton.classList.add('skeleton', `skeleton-${type}`);
            skeleton.setAttribute('aria-hidden', 'true');
            skeleton.setAttribute('role', 'presentation');

            if (options.width) skeleton.style.width = options.width;
            if (options.height) skeleton.style.height = options.height;
            if (options.className) skeleton.classList.add(options.className);

            return skeleton;
        },

        /**
         * Replace content with skeleton loader
         * @param {HTMLElement} element - Element to replace
         * @param {string} type - Skeleton type
         */
        show(element, type = 'rect') {
            element.setAttribute('data-original-content', element.innerHTML);
            element.setAttribute('data-loading', 'true');
            element.innerHTML = '';
            element.appendChild(this.create(type, {
                width: '100%',
                height: element.offsetHeight + 'px'
            }));
        },

        /**
         * Restore original content
         * @param {HTMLElement} element - Element to restore
         */
        hide(element) {
            const original = element.getAttribute('data-original-content');
            if (original !== null) {
                element.innerHTML = original;
                element.removeAttribute('data-original-content');
                element.removeAttribute('data-loading');
            }
        },

        /**
         * Create a card skeleton
         * @returns {HTMLElement}
         */
        createCard() {
            const card = document.createElement('div');
            card.classList.add('skeleton-card');
            card.setAttribute('aria-hidden', 'true');

            card.innerHTML = `
                <div class="skeleton skeleton-rect" style="height: 200px; margin-bottom: 1rem;"></div>
                <div class="skeleton skeleton-text" style="width: 70%;"></div>
                <div class="skeleton skeleton-text" style="width: 50%;"></div>
                <div class="skeleton skeleton-text" style="width: 90%;"></div>
            `;

            return card;
        },

        /**
         * Create a list skeleton
         * @param {number} count - Number of items
         * @returns {HTMLElement}
         */
        createList(count = 5) {
            const list = document.createElement('div');
            list.classList.add('skeleton-list');
            list.setAttribute('aria-hidden', 'true');

            for (let i = 0; i < count; i++) {
                const item = document.createElement('div');
                item.classList.add('skeleton-list-item');
                item.innerHTML = `
                    <div class="skeleton skeleton-circle" style="width: 40px; height: 40px;"></div>
                    <div style="flex: 1; margin-left: 1rem;">
                        <div class="skeleton skeleton-text" style="width: 60%;"></div>
                        <div class="skeleton skeleton-text" style="width: 40%;"></div>
                    </div>
                `;
                list.appendChild(item);
            }

            return list;
        }
    };

    /**
     * Button Loading - Handles button loading states
     */
    const ButtonLoading = {
        /**
         * Set button to loading state
         * @param {HTMLButtonElement} button - Button element
         * @param {string} loadingText - Optional loading text
         */
        start(button, loadingText = 'Loading...') {
            if (button.getAttribute('data-loading') === 'true') return;

            // Store original state
            button.setAttribute('data-original-text', button.innerHTML);
            button.setAttribute('data-original-width', button.offsetWidth + 'px');
            button.setAttribute('data-loading', 'true');

            // Prevent width collapse
            button.style.minWidth = button.offsetWidth + 'px';

            // Set loading state
            button.disabled = true;
            button.setAttribute('aria-busy', 'true');

            // Replace content with spinner
            button.innerHTML = `
                <span class="btn-spinner" aria-hidden="true">
                    <svg class="spinner-icon" viewBox="0 0 24 24" width="16" height="16">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" fill="none" stroke-linecap="round">
                            <animate attributeName="stroke-dasharray" values="0 150;42 150;42 150" dur="1.5s" repeatCount="indefinite"/>
                            <animate attributeName="stroke-dashoffset" values="0;-16;-59" dur="1.5s" repeatCount="indefinite"/>
                        </circle>
                    </svg>
                </span>
                <span class="btn-loading-text">${loadingText}</span>
            `;

            // Announce to screen readers
            if (window.ZumodraA11y?.announce) {
                window.ZumodraA11y.announce(loadingText, 'polite');
            }
        },

        /**
         * Remove loading state from button
         * @param {HTMLButtonElement} button - Button element
         * @param {boolean} success - Whether action was successful
         */
        stop(button, success = true) {
            if (button.getAttribute('data-loading') !== 'true') return;

            const originalText = button.getAttribute('data-original-text');

            // Brief success/error state
            if (success) {
                button.innerHTML = `<span class="btn-success-icon">&#10003;</span> Done`;
                button.classList.add('btn-success-state');
            } else {
                button.innerHTML = `<span class="btn-error-icon">&#10007;</span> Error`;
                button.classList.add('btn-error-state');
            }

            // Restore original state after brief delay
            setTimeout(() => {
                button.innerHTML = originalText;
                button.disabled = false;
                button.removeAttribute('aria-busy');
                button.removeAttribute('data-loading');
                button.removeAttribute('data-original-text');
                button.style.minWidth = '';
                button.classList.remove('btn-success-state', 'btn-error-state');
            }, 1000);
        }
    };

    /**
     * Page Loading - Handles page transition loading
     */
    const PageLoading = {
        overlay: null,

        /**
         * Create loading overlay
         */
        createOverlay() {
            if (this.overlay) return;

            this.overlay = document.createElement('div');
            this.overlay.id = 'page-loading-overlay';
            this.overlay.setAttribute('aria-hidden', 'true');
            this.overlay.innerHTML = `
                <div class="page-loader">
                    <div class="page-loader-spinner"></div>
                    <p class="page-loader-text">Loading...</p>
                </div>
            `;

            document.body.appendChild(this.overlay);
        },

        /**
         * Show page loading overlay
         * @param {string} message - Loading message
         */
        show(message = 'Loading...') {
            if (!this.overlay) this.createOverlay();

            const textEl = this.overlay.querySelector('.page-loader-text');
            if (textEl) textEl.textContent = message;

            this.overlay.classList.add('active');
            document.body.classList.add('page-loading');

            if (window.ZumodraA11y?.announce) {
                window.ZumodraA11y.announce(message, 'polite');
            }
        },

        /**
         * Hide page loading overlay
         */
        hide() {
            if (!this.overlay) return;

            this.overlay.classList.remove('active');
            document.body.classList.remove('page-loading');
        }
    };

    /**
     * Async Content Loader - Handles lazy loading content
     */
    const AsyncContentLoader = {
        /**
         * Load content into a container
         * @param {HTMLElement} container - Container element
         * @param {string} url - URL to fetch content from
         * @param {Object} options - Fetch options
         */
        async load(container, url, options = {}) {
            // Show loading state
            const skeleton = SkeletonLoader.createList(3);
            container.innerHTML = '';
            container.appendChild(skeleton);
            container.setAttribute('aria-busy', 'true');

            try {
                const response = await fetch(url, {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        ...options.headers
                    },
                    ...options
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }

                const html = await response.text();

                // Animate content in
                container.style.opacity = '0';
                container.innerHTML = html;
                container.removeAttribute('aria-busy');

                // Trigger animations
                requestAnimationFrame(() => {
                    container.style.transition = 'opacity 0.3s ease';
                    container.style.opacity = '1';
                });

                // Announce success
                if (window.ZumodraA11y?.announce) {
                    window.ZumodraA11y.announce('Content loaded', 'polite');
                }

                return true;
            } catch (error) {
                container.innerHTML = `
                    <div class="async-load-error" role="alert">
                        <p>Failed to load content.</p>
                        <button type="button" class="btn btn-sm btn-outline-primary" data-retry>
                            Try again
                        </button>
                    </div>
                `;
                container.removeAttribute('aria-busy');

                // Setup retry button
                const retryBtn = container.querySelector('[data-retry]');
                if (retryBtn) {
                    retryBtn.addEventListener('click', () => this.load(container, url, options));
                }

                console.error('AsyncContentLoader error:', error);
                return false;
            }
        }
    };

    /**
     * Progress Bar - Animated progress indicator
     */
    const ProgressBar = {
        element: null,

        /**
         * Create progress bar element
         */
        create() {
            if (this.element) return;

            this.element = document.createElement('div');
            this.element.id = 'global-progress-bar';
            this.element.setAttribute('role', 'progressbar');
            this.element.setAttribute('aria-valuemin', '0');
            this.element.setAttribute('aria-valuemax', '100');
            this.element.innerHTML = '<div class="progress-bar-fill"></div>';

            document.body.appendChild(this.element);
        },

        /**
         * Start progress animation
         */
        start() {
            if (!this.element) this.create();

            this.element.classList.add('active');
            this.set(10);

            // Simulate progress
            this.interval = setInterval(() => {
                const current = parseFloat(this.element.getAttribute('aria-valuenow') || 0);
                if (current < 90) {
                    this.set(current + Math.random() * 10);
                }
            }, 500);
        },

        /**
         * Set progress value
         * @param {number} value - Progress percentage (0-100)
         */
        set(value) {
            if (!this.element) return;

            const fill = this.element.querySelector('.progress-bar-fill');
            fill.style.width = `${value}%`;
            this.element.setAttribute('aria-valuenow', value);
        },

        /**
         * Complete and hide progress
         */
        done() {
            if (!this.element) return;

            clearInterval(this.interval);
            this.set(100);

            setTimeout(() => {
                this.element.classList.remove('active');
                this.set(0);
            }, 300);
        }
    };

    // Auto-setup loading states for forms
    function setupFormLoading() {
        document.addEventListener('submit', (e) => {
            const form = e.target;
            if (form.getAttribute('data-loading-disabled') === 'true') return;

            const submitBtn = form.querySelector('[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                ButtonLoading.start(submitBtn, submitBtn.getAttribute('data-loading-text') || 'Submitting...');
            }
        });
    }

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupFormLoading);
    } else {
        setupFormLoading();
    }

    // Expose globally
    window.ZumodraLoading = {
        Skeleton: SkeletonLoader,
        Button: ButtonLoading,
        Page: PageLoading,
        AsyncContent: AsyncContentLoader,
        Progress: ProgressBar
    };

})();
