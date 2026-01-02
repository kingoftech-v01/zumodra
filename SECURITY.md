# Zumodra Security Policy

## Overview

Zumodra implements a strict **local-only asset policy** with no external CDN dependencies. All CSS, JavaScript, fonts, icons, and other assets are served from local static files.

## Asset Policy: No External CDN

### Why Local Assets Only?

1. **Security**: Eliminates supply chain attacks via compromised CDNs
2. **Privacy**: No third-party tracking or data leakage
3. **Reliability**: No external service dependencies
4. **CSP Compliance**: Enables strict Content Security Policy
5. **Performance**: Full control over caching and delivery

### Local Asset Locations

All assets are stored in `staticfiles/`:

```
staticfiles/
├── assets/
│   ├── css/
│   │   ├── icomoon/         # Icon fonts
│   │   └── leaflet.css      # Map styles
│   ├── js/
│   │   ├── vendor/
│   │   │   ├── alpine.min.js
│   │   │   ├── htmx.min.js
│   │   │   ├── htmx-ws.min.js
│   │   │   ├── chart.min.js
│   │   │   └── Sortable.min.js
│   │   └── leaflet.js
│   ├── fonts/               # Local web fonts
│   └── images/              # Static images
└── dist/
    ├── output-tailwind.css  # Compiled Tailwind CSS
    └── output-scss.css      # Compiled SCSS
```

### Prohibited External Resources

The following external resources are **NOT ALLOWED**:

- CDN-hosted JavaScript (jsdelivr, unpkg, cdnjs, etc.)
- CDN-hosted CSS frameworks (Tailwind CDN, Bootstrap CDN)
- Google Fonts or any external font services
- External icon fonts (Font Awesome CDN, Material Icons CDN)
- External map tiles (except OpenStreetMap which is required for Leaflet)

### Adding New Dependencies

When adding new JavaScript or CSS libraries:

1. Download the minified version to `staticfiles/assets/js/vendor/` or `staticfiles/assets/css/`
2. Use Django's `{% static %}` template tag to reference the file
3. Never use external URLs in templates

Example:
```html
<!-- CORRECT -->
<script src="{% static 'assets/js/vendor/library.min.js' %}"></script>

<!-- WRONG - Never do this -->
<script src="https://cdn.example.com/library.min.js"></script>
```

---

## Content Security Policy (CSP)

### Strict CSP Configuration

Zumodra enforces a strict CSP that allows only local resources:

```python
CONTENT_SECURITY_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],  # unsafe-inline for Alpine.js
    'img-src': ["'self'", "data:", "blob:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'", "wss:"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
    'media-src': ["'self'"],
    'worker-src': ["'self'", "blob:"],
    'upgrade-insecure-requests': True,
}
```

### CSP Directives Explained

| Directive | Value | Purpose |
|-----------|-------|---------|
| `default-src` | `'self'` | Only allow resources from same origin |
| `script-src` | `'self'` | Only local JavaScript files |
| `style-src` | `'self' 'unsafe-inline'` | Local CSS + inline styles for Alpine.js |
| `img-src` | `'self' data: blob:` | Local images, data URIs, and blobs |
| `font-src` | `'self'` | Only local font files |
| `connect-src` | `'self' wss:` | XHR/Fetch to self + WebSocket |
| `frame-src` | `'none'` | Disable all iframes |
| `object-src` | `'none'` | Disable Flash/plugins |
| `frame-ancestors` | `'none'` | Prevent clickjacking |

### Testing CSP

To test CSP in development:

1. Enable report-only mode in `settings_security.py`:
   ```python
   CONTENT_SECURITY_POLICY_REPORT_ONLY = True
   ```

2. Check browser console for CSP violations

3. Fix violations before enabling enforcement

---

## Security Headers

Zumodra sets the following security headers on all responses:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | (see above) | Prevent XSS and data injection |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer information |
| `Permissions-Policy` | (restrictive) | Disable dangerous browser features |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Force HTTPS |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS protection |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolate browsing context |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin reads |

---

## Files Modified for CDN Removal

The following files were updated to use local assets:

### Error Pages
- `templates/errors/500.html` - Tailwind CSS, Alpine.js
- `templates/errors/503.html` - Tailwind CSS, Alpine.js

### Verification Pages
- `templates/accounts/verification/already_verified.html` - Tailwind CSS
- `templates/accounts/verification/token_expired.html` - Tailwind CSS
- `templates/accounts/verification/employment_response.html` - Tailwind CSS
- `templates/accounts/verification/employment_response_success.html` - Tailwind CSS

### ATS Templates
- `templates/ats/pipeline_board.html` - SortableJS

### Services Templates
- `templates/services/nearby_services.html` - Leaflet.js, Leaflet.css

### Deleted Templates
- `templates_auth/authlab/` - Entire folder (legacy templates with Google Fonts)

---

## Exception: OpenStreetMap Tiles

The only permitted external connection is to OpenStreetMap tile servers for the Leaflet maps:

```javascript
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);
```

This is required for map functionality and is explicitly allowed in CSP via the `img-src https:` directive. The Leaflet library itself is served locally.

---

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Email: security@rhematek-solutions.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

---

## Audit Checklist

Use this checklist when reviewing code changes:

- [ ] No external CDN URLs in templates
- [ ] No external font imports
- [ ] All new JS/CSS added to local staticfiles
- [ ] CSP headers verified in browser dev tools
- [ ] No CSP violations in console
- [ ] New assets use `{% static %}` tag
- [ ] No inline `<script>` tags with external sources
- [ ] No `@import` rules with external URLs

---

## Version History

| Date | Change |
|------|--------|
| 2026-01-02 | Initial strict CSP implementation, all CDN removed |

---

*Zumodra - Rhematek Solutions*
