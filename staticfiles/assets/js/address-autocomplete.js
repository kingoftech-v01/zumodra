/**
 * Address Autocomplete using Nominatim (OpenStreetMap)
 * Provides real-time address suggestions as users type in location fields
 */

class AddressAutocomplete {
    constructor(inputSelector, options = {}) {
        this.input = document.querySelector(inputSelector);
        if (!this.input) {
            console.warn(`AddressAutocomplete: Input element not found: ${inputSelector}`);
            return;
        }

        // Configuration
        this.options = {
            minLength: 3,
            debounceDelay: 300,
            maxResults: 5,
            onSelect: options.onSelect || null,
            placeholder: options.placeholder || 'Start typing an address...',
            language: options.language || 'en',
            countryCode: options.countryCode || null, // e.g., 'us', 'gb', 'fr'
            ...options
        };

        this.debounceTimer = null;
        this.suggestionsContainer = null;
        this.selectedIndex = -1;
        this.suggestions = [];

        this.init();
    }

    init() {
        // Set placeholder
        this.input.placeholder = this.options.placeholder;

        // Create suggestions container
        this.createSuggestionsContainer();

        // Attach event listeners
        this.input.addEventListener('input', (e) => this.handleInput(e));
        this.input.addEventListener('keydown', (e) => this.handleKeydown(e));
        this.input.addEventListener('focus', (e) => this.handleFocus(e));

        // Close suggestions when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.input.contains(e.target) && !this.suggestionsContainer.contains(e.target)) {
                this.hideSuggestions();
            }
        });
    }

    createSuggestionsContainer() {
        this.suggestionsContainer = document.createElement('ul');
        this.suggestionsContainer.className = 'address-autocomplete-suggestions';
        this.suggestionsContainer.style.cssText = `
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #e5e7eb;
            border-top: none;
            border-radius: 0 0 8px 8px;
            max-height: 300px;
            overflow-y: auto;
            z-index: 1000;
            list-style: none;
            margin: 0;
            padding: 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            display: none;
        `;

        // Insert after input or its parent container
        const container = this.input.closest('.form_input') || this.input.parentElement;
        if (container.style.position !== 'relative' && container.style.position !== 'absolute') {
            container.style.position = 'relative';
        }
        container.appendChild(this.suggestionsContainer);
    }

    handleInput(event) {
        const query = event.target.value.trim();

        // Clear previous timer
        clearTimeout(this.debounceTimer);

        if (query.length < this.options.minLength) {
            this.hideSuggestions();
            return;
        }

        // Debounce the search
        this.debounceTimer = setTimeout(() => {
            this.searchAddress(query);
        }, this.options.debounceDelay);
    }

    handleKeydown(event) {
        if (!this.suggestionsContainer || this.suggestionsContainer.style.display === 'none') {
            return;
        }

        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault();
                this.selectedIndex = Math.min(this.selectedIndex + 1, this.suggestions.length - 1);
                this.updateSelection();
                break;
            case 'ArrowUp':
                event.preventDefault();
                this.selectedIndex = Math.max(this.selectedIndex - 1, -1);
                this.updateSelection();
                break;
            case 'Enter':
                event.preventDefault();
                if (this.selectedIndex >= 0 && this.suggestions[this.selectedIndex]) {
                    this.selectSuggestion(this.suggestions[this.selectedIndex]);
                }
                break;
            case 'Escape':
                this.hideSuggestions();
                break;
        }
    }

    handleFocus(event) {
        // Show suggestions if there are any and input has text
        if (this.suggestions.length > 0 && this.input.value.trim().length >= this.options.minLength) {
            this.showSuggestions();
        }
    }

    async searchAddress(query) {
        try {
            // Build Nominatim API URL
            const params = new URLSearchParams({
                q: query,
                format: 'json',
                addressdetails: 1,
                limit: this.options.maxResults,
                'accept-language': this.options.language
            });

            if (this.options.countryCode) {
                params.append('countrycodes', this.options.countryCode);
            }

            const url = `https://nominatim.openstreetmap.org/search?${params.toString()}`;

            const response = await fetch(url, {
                headers: {
                    'User-Agent': 'Zumodra/1.0'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            this.suggestions = data;
            this.displaySuggestions(data);

        } catch (error) {
            console.error('Address autocomplete error:', error);
            this.hideSuggestions();
        }
    }

    displaySuggestions(suggestions) {
        // Clear previous suggestions
        this.suggestionsContainer.innerHTML = '';
        this.selectedIndex = -1;

        if (suggestions.length === 0) {
            this.hideSuggestions();
            return;
        }

        suggestions.forEach((suggestion, index) => {
            const li = document.createElement('li');
            li.className = 'address-suggestion-item';
            li.style.cssText = `
                padding: 12px 16px;
                cursor: pointer;
                border-bottom: 1px solid #f3f4f6;
                transition: background-color 0.15s ease;
            `;

            // Format the display name
            const displayName = this.formatDisplayName(suggestion);
            li.innerHTML = `
                <div class="suggestion-main" style="font-size: 14px; font-weight: 500; color: #111827;">
                    ${this.highlightMatch(displayName, this.input.value)}
                </div>
                <div class="suggestion-detail" style="font-size: 12px; color: #6b7280; margin-top: 2px;">
                    ${suggestion.type || 'Location'}
                </div>
            `;

            li.addEventListener('mouseenter', () => {
                this.selectedIndex = index;
                this.updateSelection();
            });

            li.addEventListener('click', () => {
                this.selectSuggestion(suggestion);
            });

            this.suggestionsContainer.appendChild(li);
        });

        this.showSuggestions();
    }

    formatDisplayName(suggestion) {
        // Prefer address components over display_name
        if (suggestion.address) {
            const parts = [];
            const addr = suggestion.address;

            if (addr.road || addr.street) parts.push(addr.road || addr.street);
            if (addr.city || addr.town || addr.village) parts.push(addr.city || addr.town || addr.village);
            if (addr.state) parts.push(addr.state);
            if (addr.country) parts.push(addr.country);

            return parts.join(', ') || suggestion.display_name;
        }

        return suggestion.display_name;
    }

    highlightMatch(text, query) {
        const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return text.replace(regex, '<strong style="color: #3b82f6;">$1</strong>');
    }

    updateSelection() {
        const items = this.suggestionsContainer.querySelectorAll('.address-suggestion-item');
        items.forEach((item, index) => {
            if (index === this.selectedIndex) {
                item.style.backgroundColor = '#f3f4f6';
            } else {
                item.style.backgroundColor = 'white';
            }
        });
    }

    selectSuggestion(suggestion) {
        // Set input value
        const displayName = this.formatDisplayName(suggestion);
        this.input.value = displayName;

        // Trigger change event
        const event = new Event('change', { bubbles: true });
        this.input.dispatchEvent(event);

        // Call custom callback if provided
        if (this.options.onSelect) {
            this.options.onSelect({
                displayName: displayName,
                lat: suggestion.lat,
                lon: suggestion.lon,
                address: suggestion.address,
                boundingBox: suggestion.boundingbox,
                raw: suggestion
            });
        }

        this.hideSuggestions();
    }

    showSuggestions() {
        this.suggestionsContainer.style.display = 'block';
    }

    hideSuggestions() {
        this.suggestionsContainer.style.display = 'none';
        this.selectedIndex = -1;
    }

    destroy() {
        clearTimeout(this.debounceTimer);
        if (this.suggestionsContainer && this.suggestionsContainer.parentElement) {
            this.suggestionsContainer.remove();
        }
    }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AddressAutocomplete;
}

// Make available globally
window.AddressAutocomplete = AddressAutocomplete;
