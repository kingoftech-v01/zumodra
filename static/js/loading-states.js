/**
 * Loading State Management for Zumodra
 *
 * Features:
 * - Skeleton screen generation
 * - Progress indicator
 * - Button loading states
 * - Form submission states
 * - Content placeholder animations
 *
 * WCAG 2.1 AA Compliant
 */

(function() {
    'use strict';

    // Constants
    const SKELETON_CLASS = 'skeleton';
    const LOADING_CLASS = 'is-loading';
    const TRANSITION_DURATION = 300;

    /**
     * Skeleton Screen Generator
     * Creates placeholder loading states for content
     */
    const SkeletonLoader = {
        /**
         * Generate skeleton HTML for different content types
         * @param {string} type - Type of skeleton (text, card, avatar, image, table, list)
         * @param {Object} options - Configuration options
         * @returns {string} HTML string
         */
        generate(type, options = {}) {
            const generators = {
                text: this.generateText,
                card: this.generateCard,
                avatar: this.generateAvatar,
                image: this.generateImage,
                table: this.generateTable,
                list: this.generateList,
                form: this.generateForm,
                stat: this.generateStat
            };

            const generator = generators[type] || generators.text;
            return generator.call(this, options);
        },

        /**
         * Generate text skeleton
         * @param {Object} options - {lines: number, widths: array}
         * @returns {string} HTML string
         */
        generateText(options = {}) {
            const lines = options.lines || 3;
            const widths = options.widths || ['100%', '85%', '70%'];
            const gap = options.gap || '0.75rem';

            let html = `<div class="skeleton-text" style="display: flex; flex-direction: column; gap: ${gap};" aria-hidden="true">`;

            for (let i = 0; i < lines; i++) {
                const width = widths[i % widths.length];
                html += `<div class="${SKELETON_CLASS} skeleton-line" style="height: 1rem; width: ${width}; border-radius: 4px;"></div>`;
            }

            html += '</div>';
            return html;
        },

        /**
         * Generate card skeleton
         * @param {Object} options - {showImage: boolean, showAvatar: boolean, lines: number}
         * @returns {string} HTML string
         */
        generateCard(options = {}) {
            const showImage = options.showImage !== false;
            const showAvatar = options.showAvatar || false;
            const lines = options.lines || 3;

            let html = '<div class="skeleton-card" style="background: var(--bg-elevated, #fff); border-radius: 8px; padding: 1rem; box-shadow: var(--shadow-sm);" aria-hidden="true">';

            if (showImage) {
                html += `<div class="${SKELETON_CLASS} skeleton-image" style="height: 200px; border-radius: 4px; margin-bottom: 1rem;"></div>`;
            }

            if (showAvatar) {
                html += `
                    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                        <div class="${SKELETON_CLASS} skeleton-avatar" style="width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0;"></div>
                        <div style="flex: 1;">
                            <div class="${SKELETON_CLASS}" style="height: 0.875rem; width: 60%; border-radius: 4px; margin-bottom: 0.5rem;"></div>
                            <div class="${SKELETON_CLASS}" style="height: 0.75rem; width: 40%; border-radius: 4px;"></div>
                        </div>
                    </div>
                `;
            }

            html += this.generateText({ lines, widths: ['100%', '90%', '75%'] });

            html += '</div>';
            return html;
        },

        /**
         * Generate avatar skeleton
         * @param {Object} options - {size: string, shape: string}
         * @returns {string} HTML string
         */
        generateAvatar(options = {}) {
            const size = options.size || '48px';
            const shape = options.shape || 'circle';
            const borderRadius = shape === 'circle' ? '50%' : '8px';

            return `<div class="${SKELETON_CLASS} skeleton-avatar" style="width: ${size}; height: ${size}; border-radius: ${borderRadius};" aria-hidden="true"></div>`;
        },

        /**
         * Generate image skeleton
         * @param {Object} options - {width: string, height: string, aspectRatio: string}
         * @returns {string} HTML string
         */
        generateImage(options = {}) {
            const width = options.width || '100%';
            const height = options.height || '200px';
            const aspectRatio = options.aspectRatio || null;

            let style = `width: ${width}; border-radius: 8px;`;
            if (aspectRatio) {
                style += ` aspect-ratio: ${aspectRatio};`;
            } else {
                style += ` height: ${height};`;
            }

            return `<div class="${SKELETON_CLASS} skeleton-image" style="${style}" aria-hidden="true"></div>`;
        },

        /**
         * Generate table skeleton
         * @param {Object} options - {rows: number, columns: number}
         * @returns {string} HTML string
         */
        generateTable(options = {}) {
            const rows = options.rows || 5;
            const columns = options.columns || 4;

            let html = '<div class="skeleton-table" style="width: 100%;" aria-hidden="true">';

            // Header
            html += '<div style="display: flex; gap: 1rem; padding: 1rem; background: var(--bg-secondary, #f8f9fa); border-radius: 4px 4px 0 0;">';
            for (let i = 0; i < columns; i++) {
                html += `<div class="${SKELETON_CLASS}" style="height: 1rem; flex: 1; border-radius: 4px;"></div>`;
            }
            html += '</div>';

            // Rows
            for (let r = 0; r < rows; r++) {
                html += '<div style="display: flex; gap: 1rem; padding: 1rem; border-bottom: 1px solid var(--border-primary, #dee2e6);">';
                for (let c = 0; c < columns; c++) {
                    const width = c === 0 ? '80%' : '60%';
                    html += `<div class="${SKELETON_CLASS}" style="height: 1rem; width: ${width}; flex: 1; border-radius: 4px;"></div>`;
                }
                html += '</div>';
            }

            html += '</div>';
            return html;
        },

        /**
         * Generate list skeleton
         * @param {Object} options - {items: number, showAvatar: boolean, showAction: boolean}
         * @returns {string} HTML string
         */
        generateList(options = {}) {
            const items = options.items || 5;
            const showAvatar = options.showAvatar !== false;
            const showAction = options.showAction || false;

            let html = '<div class="skeleton-list" style="display: flex; flex-direction: column; gap: 1rem;" aria-hidden="true">';

            for (let i = 0; i < items; i++) {
                html += '<div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--bg-elevated, #fff); border-radius: 8px;">';

                if (showAvatar) {
                    html += `<div class="${SKELETON_CLASS}" style="width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0;"></div>`;
                }

                html += `
                    <div style="flex: 1;">
                        <div class="${SKELETON_CLASS}" style="height: 1rem; width: 70%; border-radius: 4px; margin-bottom: 0.5rem;"></div>
                        <div class="${SKELETON_CLASS}" style="height: 0.75rem; width: 50%; border-radius: 4px;"></div>
                    </div>
                `;

                if (showAction) {
                    html += `<div class="${SKELETON_CLASS}" style="width: 80px; height: 36px; border-radius: 4px; flex-shrink: 0;"></div>`;
                }

                html += '</div>';
            }

            html += '</div>';
            return html;
        },

        /**
         * Generate form skeleton
         * @param {Object} options - {fields: number}
         * @returns {string} HTML string
         */
        generateForm(options = {}) {
            const fields = options.fields || 4;

            let html = '<div class="skeleton-form" style="display: flex; flex-direction: column; gap: 1.5rem;" aria-hidden="true">';

            for (let i = 0; i < fields; i++) {
                html += `
                    <div>
                        <div class="${SKELETON_CLASS}" style="height: 0.875rem; width: 30%; border-radius: 4px; margin-bottom: 0.5rem;"></div>
                        <div class="${SKELETON_CLASS}" style="height: 40px; width: 100%; border-radius: 4px;"></div>
                    </div>
                `;
            }

            html += `<div class="${SKELETON_CLASS}" style="height: 44px; width: 120px; border-radius: 4px; margin-top: 0.5rem;"></div>`;
            html += '</div>';
            return html;
        },

        /**
         * Generate stat card skeleton
         * @param {Object} options - {showIcon: boolean}
         * @returns {string} HTML string
         */
        generateStat(options = {}) {
            const showIcon = options.showIcon !== false;

            let html = `<div class="skeleton-stat" style="padding: 1.5rem; background: var(--bg-elevated, #fff); border-radius: 8px;" aria-hidden="true">`;

            html += '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">';
            html += `<div class="${SKELETON_CLASS}" style="height: 0.875rem; width: 40%; border-radius: 4px;"></div>`;
            if (showIcon) {
                html += `<div class="${SKELETON_CLASS}" style="width: 32px; height: 32px; border-radius: 8px;"></div>`;
            }
            html += '</div>';

            html += `<div class="${SKELETON_CLASS}" style="height: 2rem; width: 60%; border-radius: 4px; margin-bottom: 0.5rem;"></div>`;
            html += `<div class="${SKELETON_CLASS}" style="height: 0.75rem; width: 35%; border-radius: 4px;"></div>`;

            html += '</div>';
            return html;
        },

        /**
         * Apply skeleton to an element
         * @param {HTMLElement} element - Target element
         * @param {string} type - Skeleton type
         * @param {Object} options - Configuration options
         */
        apply(element, type, options = {}) {
            if (!element) return;

            // Store original content
            element.dataset.originalContent = element.innerHTML;

            // Set loading state
            element.setAttribute('aria-busy', 'true');
            element.classList.add(LOADING_CLASS);

            // Insert skeleton
            element.innerHTML = this.generate(type, options);

            // Announce loading state
            if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                window.ZumodraA11y.Announcer.polite('Loading content');
            }
        },

        /**
         * Remove skeleton and restore content
         * @param {HTMLElement} element - Target element
         * @param {string} newContent - New content to insert (optional)
         */
        remove(element, newContent = null) {
            if (!element) return;

            // Remove loading state
            element.removeAttribute('aria-busy');
            element.classList.remove(LOADING_CLASS);

            // Restore or set new content
            if (newContent !== null) {
                element.innerHTML = newContent;
            } else if (element.dataset.originalContent) {
                element.innerHTML = element.dataset.originalContent;
                delete element.dataset.originalContent;
            }

            // Announce content loaded
            if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                window.ZumodraA11y.Announcer.polite('Content loaded');
            }
        }
    };

    /**
     * Progress Indicator
     * Shows progress for long-running operations
     */
    const ProgressIndicator = {
        container: null,
        bar: null,
        text: null,

        /**
         * Create progress indicator element
         * @param {Object} options - Configuration options
         * @returns {HTMLElement} Progress container
         */
        create(options = {}) {
            const {
                showText = true,
                showPercentage = true,
                variant = 'linear', // linear, circular
                color = 'var(--brand-primary, #0d6efd)',
                height = '4px'
            } = options;

            this.container = document.createElement('div');
            this.container.className = 'progress-indicator';
            this.container.setAttribute('role', 'progressbar');
            this.container.setAttribute('aria-valuemin', '0');
            this.container.setAttribute('aria-valuemax', '100');
            this.container.setAttribute('aria-valuenow', '0');

            if (variant === 'linear') {
                this.container.innerHTML = `
                    <div class="progress-indicator__track" style="width: 100%; height: ${height}; background: var(--bg-tertiary, #e9ecef); border-radius: 999px; overflow: hidden;">
                        <div class="progress-indicator__bar" style="width: 0%; height: 100%; background: ${color}; transition: width 0.3s ease; border-radius: 999px;"></div>
                    </div>
                    ${showText ? `<div class="progress-indicator__text" style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-secondary);">${showPercentage ? '0%' : 'Loading...'}</div>` : ''}
                `;
            } else if (variant === 'circular') {
                const size = options.size || 60;
                const strokeWidth = options.strokeWidth || 4;
                const radius = (size - strokeWidth) / 2;
                const circumference = 2 * Math.PI * radius;

                this.container.innerHTML = `
                    <svg width="${size}" height="${size}" class="progress-indicator__circular">
                        <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="var(--bg-tertiary, #e9ecef)" stroke-width="${strokeWidth}"/>
                        <circle class="progress-indicator__bar" cx="${size / 2}" cy="${size / 2}" r="${radius}" fill="none" stroke="${color}" stroke-width="${strokeWidth}" stroke-dasharray="${circumference}" stroke-dashoffset="${circumference}" stroke-linecap="round" transform="rotate(-90 ${size / 2} ${size / 2})" style="transition: stroke-dashoffset 0.3s ease;"/>
                    </svg>
                    ${showText && showPercentage ? `<div class="progress-indicator__text" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 0.875rem; font-weight: 600;">0%</div>` : ''}
                `;
                this.container.style.position = 'relative';
                this.container.style.display = 'inline-block';
            }

            this.bar = this.container.querySelector('.progress-indicator__bar');
            this.text = this.container.querySelector('.progress-indicator__text');

            return this.container;
        },

        /**
         * Update progress value
         * @param {number} value - Progress value (0-100)
         * @param {string} label - Optional text label
         */
        update(value, label = null) {
            value = Math.max(0, Math.min(100, value));

            this.container.setAttribute('aria-valuenow', value);

            if (this.bar) {
                if (this.bar.tagName === 'circle') {
                    const radius = parseFloat(this.bar.getAttribute('r'));
                    const circumference = 2 * Math.PI * radius;
                    this.bar.style.strokeDashoffset = circumference * (1 - value / 100);
                } else {
                    this.bar.style.width = `${value}%`;
                }
            }

            if (this.text) {
                this.text.textContent = label || `${Math.round(value)}%`;
            }

            // Announce at milestones
            if (value % 25 === 0 && window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                window.ZumodraA11y.Announcer.polite(`Progress: ${Math.round(value)}%`);
            }
        },

        /**
         * Set indeterminate state
         */
        setIndeterminate() {
            this.container.removeAttribute('aria-valuenow');

            if (this.bar && this.bar.tagName !== 'circle') {
                this.bar.style.width = '30%';
                this.bar.style.animation = 'progress-indeterminate 1.5s infinite ease-in-out';
            }

            if (this.text) {
                this.text.textContent = 'Loading...';
            }
        },

        /**
         * Complete and hide progress
         * @param {number} delay - Delay before hiding (ms)
         */
        complete(delay = 500) {
            this.update(100, 'Complete');

            setTimeout(() => {
                this.container.style.opacity = '0';
                setTimeout(() => {
                    if (this.container.parentNode) {
                        this.container.parentNode.removeChild(this.container);
                    }
                }, TRANSITION_DURATION);
            }, delay);
        }
    };

    /**
     * Button Loading State Manager
     */
    const ButtonLoader = {
        /**
         * Set button to loading state
         * @param {HTMLElement} button - Button element
         * @param {Object} options - Configuration options
         */
        start(button, options = {}) {
            if (!button || button.classList.contains(LOADING_CLASS)) return;

            const {
                text = 'Loading...',
                showSpinner = true,
                disableButton = true
            } = options;

            // Store original state
            button.dataset.originalText = button.innerHTML;
            button.dataset.originalWidth = button.style.width;
            button.dataset.originalDisabled = button.disabled;

            // Set fixed width to prevent layout shift
            const rect = button.getBoundingClientRect();
            button.style.width = `${rect.width}px`;

            // Set loading state
            button.classList.add(LOADING_CLASS);

            if (disableButton) {
                button.disabled = true;
            }

            button.setAttribute('aria-busy', 'true');

            // Set loading content
            let loadingContent = '';
            if (showSpinner) {
                loadingContent += `
                    <span class="button-spinner" aria-hidden="true" style="display: inline-block; width: 1em; height: 1em; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin 0.75s linear infinite; margin-right: 0.5em;"></span>
                `;
            }
            loadingContent += `<span>${text}</span>`;

            button.innerHTML = loadingContent;
        },

        /**
         * Remove loading state from button
         * @param {HTMLElement} button - Button element
         * @param {Object} options - Configuration options
         */
        stop(button, options = {}) {
            if (!button || !button.classList.contains(LOADING_CLASS)) return;

            const {
                success = null, // null, true, false
                successText = 'Done!',
                errorText = 'Error',
                showStatus = true,
                statusDuration = 1500
            } = options;

            button.classList.remove(LOADING_CLASS);
            button.removeAttribute('aria-busy');

            // Show success/error status
            if (showStatus && success !== null) {
                const statusIcon = success
                    ? '<svg style="width: 1em; height: 1em; margin-right: 0.5em;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'
                    : '<svg style="width: 1em; height: 1em; margin-right: 0.5em;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';

                button.innerHTML = statusIcon + (success ? successText : errorText);
                button.classList.add(success ? 'btn-success' : 'btn-danger');

                setTimeout(() => {
                    this.restore(button);
                }, statusDuration);
            } else {
                this.restore(button);
            }
        },

        /**
         * Restore button to original state
         * @param {HTMLElement} button - Button element
         */
        restore(button) {
            if (!button) return;

            button.innerHTML = button.dataset.originalText || button.innerHTML;
            button.style.width = button.dataset.originalWidth || '';
            button.disabled = button.dataset.originalDisabled === 'true';

            button.classList.remove('btn-success', 'btn-danger');

            delete button.dataset.originalText;
            delete button.dataset.originalWidth;
            delete button.dataset.originalDisabled;
        }
    };

    /**
     * Form Submission State Manager
     */
    const FormLoader = {
        /**
         * Set form to loading state
         * @param {HTMLFormElement} form - Form element
         * @param {Object} options - Configuration options
         */
        start(form, options = {}) {
            if (!form || form.classList.contains(LOADING_CLASS)) return;

            const {
                disableInputs = true,
                showOverlay = true,
                loadingText = 'Submitting...'
            } = options;

            // Set loading state
            form.classList.add(LOADING_CLASS);
            form.setAttribute('aria-busy', 'true');

            // Disable inputs
            if (disableInputs) {
                const inputs = form.querySelectorAll('input, select, textarea, button');
                inputs.forEach(input => {
                    input.dataset.wasDisabled = input.disabled;
                    input.disabled = true;
                });
            }

            // Find and update submit button
            const submitBtn = form.querySelector('[type="submit"], button:not([type])');
            if (submitBtn) {
                ButtonLoader.start(submitBtn, { text: loadingText });
            }

            // Add overlay if requested
            if (showOverlay) {
                const overlay = document.createElement('div');
                overlay.className = 'form-loading-overlay';
                overlay.style.cssText = 'position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255, 255, 255, 0.8); display: flex; align-items: center; justify-content: center; z-index: 10;';
                overlay.innerHTML = `
                    <div style="text-align: center;">
                        <div class="button-spinner" style="width: 2rem; height: 2rem; border: 3px solid var(--brand-primary); border-right-color: transparent; border-radius: 50%; animation: spin 0.75s linear infinite; margin: 0 auto 0.5rem;"></div>
                        <div style="color: var(--text-secondary); font-size: 0.875rem;">${loadingText}</div>
                    </div>
                `;

                form.style.position = 'relative';
                form.appendChild(overlay);
            }

            // Announce
            if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                window.ZumodraA11y.Announcer.polite('Form submitting');
            }
        },

        /**
         * Remove loading state from form
         * @param {HTMLFormElement} form - Form element
         * @param {Object} options - Configuration options
         */
        stop(form, options = {}) {
            if (!form) return;

            const {
                success = null,
                message = null
            } = options;

            form.classList.remove(LOADING_CLASS);
            form.removeAttribute('aria-busy');

            // Re-enable inputs
            const inputs = form.querySelectorAll('input, select, textarea, button');
            inputs.forEach(input => {
                input.disabled = input.dataset.wasDisabled === 'true';
                delete input.dataset.wasDisabled;
            });

            // Update submit button
            const submitBtn = form.querySelector('[type="submit"], button:not([type])');
            if (submitBtn) {
                ButtonLoader.stop(submitBtn, {
                    success,
                    successText: message || 'Submitted!',
                    errorText: message || 'Error'
                });
            }

            // Remove overlay
            const overlay = form.querySelector('.form-loading-overlay');
            if (overlay) {
                overlay.remove();
            }

            // Announce result
            if (window.ZumodraA11y && window.ZumodraA11y.Announcer) {
                const announcement = success ? 'Form submitted successfully' : 'Form submission failed';
                window.ZumodraA11y.Announcer.polite(message || announcement);
            }
        }
    };

    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes progress-indeterminate {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(400%); }
        }

        @keyframes skeleton-shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }

        .${SKELETON_CLASS} {
            background: linear-gradient(90deg, var(--bg-tertiary, #e9ecef) 25%, var(--bg-secondary, #f8f9fa) 50%, var(--bg-tertiary, #e9ecef) 75%);
            background-size: 200% 100%;
            animation: skeleton-shimmer 1.5s ease-in-out infinite;
        }

        .${LOADING_CLASS} {
            pointer-events: none;
        }

        .button-spinner {
            vertical-align: middle;
        }

        /* Reduced motion support */
        @media (prefers-reduced-motion: reduce) {
            .${SKELETON_CLASS} {
                animation: none;
                background: var(--bg-tertiary, #e9ecef);
            }

            .button-spinner,
            .progress-indicator__bar {
                animation: none;
            }
        }
    `;
    document.head.appendChild(style);

    // Expose to global scope
    window.ZumodraLoading = {
        Skeleton: SkeletonLoader,
        Progress: ProgressIndicator,
        Button: ButtonLoader,
        Form: FormLoader,
        LOADING_CLASS
    };

    // Dispatch ready event
    window.dispatchEvent(new CustomEvent('zumodra:loading-ready'));

})();
