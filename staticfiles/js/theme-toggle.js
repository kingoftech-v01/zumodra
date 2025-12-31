/**
 * Dark Mode Theme Toggle System
 *
 * Features:
 * - System preference detection via prefers-color-scheme
 * - LocalStorage persistence for user preference
 * - Smooth transitions between themes
 * - No flash of unstyled content (FOUC prevention)
 * - Event-based architecture for external integrations
 *
 * WCAG 2.1 AA Compliant
 */

(function() {
    'use strict';

    // Constants
    const STORAGE_KEY = 'zumodra-theme';
    const THEME_ATTRIBUTE = 'data-theme';
    const TRANSITION_DURATION = 300;
    const THEMES = {
        LIGHT: 'light',
        DARK: 'dark',
        SYSTEM: 'system'
    };

    // Theme Manager Class
    class ThemeManager {
        constructor() {
            this.currentTheme = null;
            this.systemPreference = null;
            this.mediaQuery = null;
            this.transitionTimeout = null;
            this.listeners = new Set();

            this.init();
        }

        /**
         * Initialize the theme manager
         */
        init() {
            // Prevent FOUC by setting theme before DOM loads
            this.applyInitialTheme();

            // Set up system preference detection
            this.setupSystemPreferenceListener();

            // Wait for DOM to be ready for toggle buttons
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.setupToggleButtons());
            } else {
                this.setupToggleButtons();
            }
        }

        /**
         * Apply initial theme immediately to prevent FOUC
         */
        applyInitialTheme() {
            const savedTheme = this.getSavedTheme();
            const systemTheme = this.getSystemPreference();

            if (savedTheme && savedTheme !== THEMES.SYSTEM) {
                this.setTheme(savedTheme, false);
            } else {
                this.setTheme(systemTheme, false);
                if (!savedTheme) {
                    this.saveTheme(THEMES.SYSTEM);
                }
            }
        }

        /**
         * Get saved theme from localStorage
         * @returns {string|null} Saved theme or null
         */
        getSavedTheme() {
            try {
                return localStorage.getItem(STORAGE_KEY);
            } catch (e) {
                console.warn('LocalStorage not available:', e);
                return null;
            }
        }

        /**
         * Save theme to localStorage
         * @param {string} theme - Theme to save
         */
        saveTheme(theme) {
            try {
                localStorage.setItem(STORAGE_KEY, theme);
            } catch (e) {
                console.warn('Could not save theme to localStorage:', e);
            }
        }

        /**
         * Get system color scheme preference
         * @returns {string} 'dark' or 'light'
         */
        getSystemPreference() {
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                return THEMES.DARK;
            }
            return THEMES.LIGHT;
        }

        /**
         * Set up listener for system preference changes
         */
        setupSystemPreferenceListener() {
            if (!window.matchMedia) return;

            this.mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

            const handleChange = (e) => {
                this.systemPreference = e.matches ? THEMES.DARK : THEMES.LIGHT;

                // Only apply system preference if user hasn't set a specific preference
                const savedTheme = this.getSavedTheme();
                if (!savedTheme || savedTheme === THEMES.SYSTEM) {
                    this.setTheme(this.systemPreference, true);
                }

                this.notifyListeners('system-change', this.systemPreference);
            };

            // Modern browsers
            if (this.mediaQuery.addEventListener) {
                this.mediaQuery.addEventListener('change', handleChange);
            } else {
                // Legacy support
                this.mediaQuery.addListener(handleChange);
            }

            // Initialize system preference
            this.systemPreference = this.mediaQuery.matches ? THEMES.DARK : THEMES.LIGHT;
        }

        /**
         * Set theme with optional transition
         * @param {string} theme - Theme to apply
         * @param {boolean} animate - Whether to animate the transition
         */
        setTheme(theme, animate = true) {
            const effectiveTheme = theme === THEMES.SYSTEM ? this.getSystemPreference() : theme;

            if (this.currentTheme === effectiveTheme) return;

            const root = document.documentElement;
            const body = document.body;

            if (animate) {
                // Add transition class for smooth animation
                root.classList.add('theme-transitioning');
                if (body) body.classList.add('theme-transitioning');
            }

            // Apply theme attribute
            root.setAttribute(THEME_ATTRIBUTE, effectiveTheme);

            // Also set class for CSS specificity
            root.classList.remove('theme-light', 'theme-dark');
            root.classList.add(`theme-${effectiveTheme}`);

            // Update meta theme-color for mobile browsers
            this.updateMetaThemeColor(effectiveTheme);

            // Update color-scheme property for native form controls
            root.style.colorScheme = effectiveTheme;

            this.currentTheme = effectiveTheme;

            // Update toggle buttons
            this.updateToggleButtons(effectiveTheme);

            if (animate) {
                // Remove transition class after animation completes
                clearTimeout(this.transitionTimeout);
                this.transitionTimeout = setTimeout(() => {
                    root.classList.remove('theme-transitioning');
                    if (body) body.classList.remove('theme-transitioning');
                }, TRANSITION_DURATION);
            }

            // Notify listeners
            this.notifyListeners('theme-change', effectiveTheme);

            // Dispatch custom event for external integrations
            window.dispatchEvent(new CustomEvent('zumodra:theme-change', {
                detail: {
                    theme: effectiveTheme,
                    savedPreference: theme,
                    isSystem: theme === THEMES.SYSTEM
                }
            }));
        }

        /**
         * Update meta theme-color tag for mobile browsers
         * @param {string} theme - Current theme
         */
        updateMetaThemeColor(theme) {
            let metaThemeColor = document.querySelector('meta[name="theme-color"]');

            if (!metaThemeColor) {
                metaThemeColor = document.createElement('meta');
                metaThemeColor.name = 'theme-color';
                document.head.appendChild(metaThemeColor);
            }

            // Set appropriate colors
            const colors = {
                light: '#ffffff',
                dark: '#1a1a2e'
            };

            metaThemeColor.content = colors[theme] || colors.light;
        }

        /**
         * Toggle between light and dark themes
         */
        toggle() {
            const newTheme = this.currentTheme === THEMES.DARK ? THEMES.LIGHT : THEMES.DARK;
            this.setTheme(newTheme, true);
            this.saveTheme(newTheme);

            // Announce change for screen readers
            this.announceThemeChange(newTheme);
        }

        /**
         * Set specific theme
         * @param {string} theme - Theme to set (light, dark, or system)
         */
        set(theme) {
            if (!Object.values(THEMES).includes(theme)) {
                console.warn('Invalid theme:', theme);
                return;
            }

            this.setTheme(theme, true);
            this.saveTheme(theme);
            this.announceThemeChange(theme);
        }

        /**
         * Reset to system preference
         */
        resetToSystem() {
            this.set(THEMES.SYSTEM);
        }

        /**
         * Announce theme change for screen readers
         * @param {string} theme - New theme
         */
        announceThemeChange(theme) {
            const announcer = document.getElementById('theme-announcer') || this.createAnnouncer();
            const effectiveTheme = theme === THEMES.SYSTEM ? this.getSystemPreference() : theme;
            const message = `Theme changed to ${effectiveTheme} mode`;

            announcer.textContent = message;
        }

        /**
         * Create ARIA live region for announcements
         * @returns {HTMLElement} Announcer element
         */
        createAnnouncer() {
            const announcer = document.createElement('div');
            announcer.id = 'theme-announcer';
            announcer.setAttribute('role', 'status');
            announcer.setAttribute('aria-live', 'polite');
            announcer.setAttribute('aria-atomic', 'true');
            announcer.className = 'sr-only';
            document.body.appendChild(announcer);
            return announcer;
        }

        /**
         * Set up toggle button event listeners
         */
        setupToggleButtons() {
            const toggleButtons = document.querySelectorAll('[data-theme-toggle]');

            toggleButtons.forEach(button => {
                button.addEventListener('click', (e) => {
                    e.preventDefault();
                    const targetTheme = button.getAttribute('data-theme-toggle');

                    if (targetTheme === 'toggle') {
                        this.toggle();
                    } else if (targetTheme) {
                        this.set(targetTheme);
                    } else {
                        this.toggle();
                    }
                });

                // Keyboard support
                button.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        button.click();
                    }
                });
            });

            // Initial button state update
            this.updateToggleButtons(this.currentTheme);
        }

        /**
         * Update toggle button states
         * @param {string} theme - Current theme
         */
        updateToggleButtons(theme) {
            const toggleButtons = document.querySelectorAll('[data-theme-toggle]');

            toggleButtons.forEach(button => {
                const isDark = theme === THEMES.DARK;

                // Update aria-pressed for toggle buttons
                if (button.getAttribute('data-theme-toggle') === 'toggle') {
                    button.setAttribute('aria-pressed', isDark);
                }

                // Update aria-label
                const newLabel = isDark ? 'Switch to light mode' : 'Switch to dark mode';
                button.setAttribute('aria-label', newLabel);

                // Update icon classes if present
                const sunIcon = button.querySelector('.theme-icon-light');
                const moonIcon = button.querySelector('.theme-icon-dark');

                if (sunIcon && moonIcon) {
                    sunIcon.style.display = isDark ? 'block' : 'none';
                    moonIcon.style.display = isDark ? 'none' : 'block';
                }

                // Update data attribute for CSS styling
                button.setAttribute('data-current-theme', theme);
            });
        }

        /**
         * Add event listener for theme changes
         * @param {Function} callback - Callback function
         */
        onChange(callback) {
            if (typeof callback === 'function') {
                this.listeners.add(callback);
            }
        }

        /**
         * Remove event listener
         * @param {Function} callback - Callback to remove
         */
        offChange(callback) {
            this.listeners.delete(callback);
        }

        /**
         * Notify all listeners of changes
         * @param {string} type - Event type
         * @param {string} theme - Current theme
         */
        notifyListeners(type, theme) {
            this.listeners.forEach(callback => {
                try {
                    callback({ type, theme });
                } catch (e) {
                    console.error('Theme listener error:', e);
                }
            });
        }

        /**
         * Get current theme
         * @returns {string} Current theme
         */
        getTheme() {
            return this.currentTheme;
        }

        /**
         * Check if dark mode is active
         * @returns {boolean} True if dark mode
         */
        isDark() {
            return this.currentTheme === THEMES.DARK;
        }

        /**
         * Check if light mode is active
         * @returns {boolean} True if light mode
         */
        isLight() {
            return this.currentTheme === THEMES.LIGHT;
        }
    }

    // Create and expose global instance
    const themeManager = new ThemeManager();

    // Expose to global scope
    window.ZumodraTheme = themeManager;
    window.ZumodraTheme.THEMES = THEMES;

    // Add inline script for immediate FOUC prevention
    // This should be included in <head> before any CSS loads
    window.ZumodraTheme.getInlineScript = function() {
        return `
            (function() {
                var theme = localStorage.getItem('${STORAGE_KEY}');
                var systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
                var effectiveTheme = theme && theme !== 'system' ? theme : (systemDark ? 'dark' : 'light');
                document.documentElement.setAttribute('data-theme', effectiveTheme);
                document.documentElement.classList.add('theme-' + effectiveTheme);
                document.documentElement.style.colorScheme = effectiveTheme;
            })();
        `;
    };

})();
