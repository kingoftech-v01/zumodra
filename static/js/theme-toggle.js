/**
 * Zumodra Theme Toggle System
 *
 * Handles dark/light mode switching with:
 * - System preference detection
 * - LocalStorage persistence
 * - Smooth transitions
 * - Accessibility support
 */

(function() {
    'use strict';

    const THEME_KEY = 'zumodra-theme';
    const THEMES = {
        LIGHT: 'light',
        DARK: 'dark',
        SYSTEM: 'system'
    };

    /**
     * ThemeManager - Singleton for managing theme state
     */
    const ThemeManager = {
        currentTheme: THEMES.SYSTEM,
        mediaQuery: null,

        /**
         * Initialize the theme manager
         */
        init() {
            this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            this.loadSavedTheme();
            this.applyTheme();
            this.setupEventListeners();
            this.setupMediaQueryListener();
        },

        /**
         * Load saved theme from localStorage
         */
        loadSavedTheme() {
            const saved = localStorage.getItem(THEME_KEY);
            if (saved && Object.values(THEMES).includes(saved)) {
                this.currentTheme = saved;
            }
        },

        /**
         * Save theme preference to localStorage
         * @param {string} theme - Theme to save
         */
        saveTheme(theme) {
            localStorage.setItem(THEME_KEY, theme);
            this.currentTheme = theme;
        },

        /**
         * Get the effective theme (resolves 'system' to actual theme)
         * @returns {string} - 'light' or 'dark'
         */
        getEffectiveTheme() {
            if (this.currentTheme === THEMES.SYSTEM) {
                return this.mediaQuery.matches ? THEMES.DARK : THEMES.LIGHT;
            }
            return this.currentTheme;
        },

        /**
         * Apply the current theme to the document
         */
        applyTheme() {
            const effectiveTheme = this.getEffectiveTheme();
            const html = document.documentElement;

            // Add transition class for smooth theme change
            html.classList.add('theme-transitioning');

            // Set theme attribute
            html.setAttribute('data-theme', effectiveTheme);

            // Update body class for legacy CSS
            document.body.classList.remove('theme-light', 'theme-dark');
            document.body.classList.add(`theme-${effectiveTheme}`);

            // Update meta theme-color for mobile browsers
            this.updateMetaThemeColor(effectiveTheme);

            // Update toggle buttons
            this.updateToggleButtons();

            // Remove transition class after animation completes
            setTimeout(() => {
                html.classList.remove('theme-transitioning');
            }, 300);

            // Dispatch custom event for other components
            window.dispatchEvent(new CustomEvent('themechange', {
                detail: { theme: effectiveTheme, preference: this.currentTheme }
            }));
        },

        /**
         * Update meta theme-color for mobile browsers
         * @param {string} theme - Current theme
         */
        updateMetaThemeColor(theme) {
            let metaThemeColor = document.querySelector('meta[name="theme-color"]');

            if (!metaThemeColor) {
                metaThemeColor = document.createElement('meta');
                metaThemeColor.name = 'theme-color';
                document.head.appendChild(metaThemeColor);
            }

            metaThemeColor.content = theme === THEMES.DARK ? '#1a1a2e' : '#ffffff';
        },

        /**
         * Update all toggle button states
         */
        updateToggleButtons() {
            const effectiveTheme = this.getEffectiveTheme();
            const buttons = document.querySelectorAll('[data-theme-toggle]');

            buttons.forEach(button => {
                const sunIcon = button.querySelector('.theme-icon-light');
                const moonIcon = button.querySelector('.theme-icon-dark');
                const systemIcon = button.querySelector('.theme-icon-system');

                // Update aria-pressed state
                button.setAttribute('aria-pressed', effectiveTheme === THEMES.DARK);

                // Update visible icon
                if (sunIcon) sunIcon.style.display = effectiveTheme === THEMES.LIGHT ? 'block' : 'none';
                if (moonIcon) moonIcon.style.display = effectiveTheme === THEMES.DARK ? 'block' : 'none';
                if (systemIcon) systemIcon.style.display = this.currentTheme === THEMES.SYSTEM ? 'block' : 'none';

                // Update button text for screen readers
                const srText = button.querySelector('.sr-only');
                if (srText) {
                    srText.textContent = `Current theme: ${effectiveTheme}. Click to toggle.`;
                }
            });
        },

        /**
         * Toggle to next theme in cycle: light -> dark -> system -> light
         */
        toggleTheme() {
            const order = [THEMES.LIGHT, THEMES.DARK, THEMES.SYSTEM];
            const currentIndex = order.indexOf(this.currentTheme);
            const nextIndex = (currentIndex + 1) % order.length;

            this.setTheme(order[nextIndex]);
        },

        /**
         * Set a specific theme
         * @param {string} theme - Theme to set
         */
        setTheme(theme) {
            if (!Object.values(THEMES).includes(theme)) {
                console.warn(`Invalid theme: ${theme}`);
                return;
            }

            this.saveTheme(theme);
            this.applyTheme();
        },

        /**
         * Setup event listeners for toggle buttons
         */
        setupEventListeners() {
            // Handle all theme toggle buttons
            document.addEventListener('click', (e) => {
                const toggleBtn = e.target.closest('[data-theme-toggle]');
                if (toggleBtn) {
                    e.preventDefault();
                    this.toggleTheme();
                }
            });

            // Handle theme selection from dropdown menus
            document.addEventListener('click', (e) => {
                const themeOption = e.target.closest('[data-theme-set]');
                if (themeOption) {
                    e.preventDefault();
                    const theme = themeOption.getAttribute('data-theme-set');
                    this.setTheme(theme);
                }
            });

            // Keyboard support
            document.addEventListener('keydown', (e) => {
                const toggleBtn = e.target.closest('[data-theme-toggle]');
                if (toggleBtn && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    this.toggleTheme();
                }
            });
        },

        /**
         * Listen for system theme changes
         */
        setupMediaQueryListener() {
            this.mediaQuery.addEventListener('change', () => {
                if (this.currentTheme === THEMES.SYSTEM) {
                    this.applyTheme();
                }
            });
        }
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => ThemeManager.init());
    } else {
        ThemeManager.init();
    }

    // Expose ThemeManager globally for programmatic access
    window.ZumodraTheme = ThemeManager;

})();
