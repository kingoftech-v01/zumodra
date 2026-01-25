# FreelanHub - Section Components

This directory contains reusable section components extracted from the freelancer template files.

## Overview

- **Total Components**: 106 HTML section files
- **Source Files**: 11 freelancer template files (freelancer2.html through freelancer12.html)
- **Organization**: 18 subdirectories by section type

## Directory Structure

```
components/sections/
├── banner/          (7 files)   - Call-to-action banner sections
├── benefit/         (13 files)  - Platform benefits/features sections
├── blog/            (9 files)   - Blog listing sections
├── brand/           (6 files)   - Partner/brand logo sections
├── categories/      (6 files)   - Job/service category browsing
├── counter/         (1 file)    - Statistics/counter sections
├── download/        (3 files)   - App download sections
├── explore/         (1 file)    - Exploration sections
├── faqs/            (1 file)    - FAQ sections
├── freelancers/     (7 files)   - Freelancer listings/showcases
├── jobs/            (7 files)   - Job listing sections
├── other/           (10 files)  - Miscellaneous sections
├── pricing/         (2 files)   - Pricing table sections
├── projects/        (4 files)   - Project portfolio sections
├── services/        (8 files)   - Service listing sections
├── slider/          (11 files)  - Hero slider sections
├── testimonials/    (9 files)   - Customer testimonial sections
└── video/           (1 file)    - Video embed sections
```

## Naming Convention

Component files follow this naming pattern:

**Format**: `{type}-style-{source-file-number}[-v{variant}].html`

**Examples**:
- `slider-style-3.html` - Slider from freelancer3.html
- `benefit-style-5-v1.html` - First benefit section from freelancer5.html
- `benefit-style-5-v2.html` - Second benefit section from freelancer5.html
- `testimonials-style-7.html` - Testimonials from freelancer7.html

**Rules**:
- Section type in lowercase with hyphens
- "style-" followed by source file number (2-12)
- Variant suffix (-v1, -v2, etc.) when multiple sections of same type exist in one file
- Always `.html` extension

## File Structure

Each component file contains:

1. **HTML Comment** identifying the section type (e.g., `<!-- Slider -->`)
2. **Complete `<section>` block** with all content and classes
3. **Adjusted asset paths** using `../../assets/` for correct relative paths

**What's NOT included**:
- DOCTYPE declarations
- `<html>`, `<head>`, `<body>` tags
- Header or footer elements
- JavaScript files or external scripts

## Asset Paths

All asset references have been adjusted for the new component location:

- **Original**: `./assets/images/...`
- **Updated**: `../../assets/images/...`

This ensures images, CSS, and other assets load correctly when components are included in pages.

## Usage Examples

### Direct Include (Server-side)

**PHP**:
```php
<?php include 'components/sections/slider/slider-style-3.html'; ?>
```

**Node.js/Express (EJS)**:
```ejs
<%- include('../components/sections/slider/slider-style-3.html') %>
```

**Python/Django**:
```django
{% include 'components/sections/slider/slider-style-3.html' %}
```

### Build Process Integration

**Webpack/Vite**:
```javascript
import sliderHTML from './components/sections/slider/slider-style-3.html';
document.getElementById('app').innerHTML = sliderHTML;
```

**Static Site Generator**:
```markdown
<!-- In your markdown or template -->
@@include('components/sections/slider/slider-style-3.html')
```

## Component Categories

### Hero Sections
- **Location**: `slider/`
- **Files**: 11 variants (one from each template)
- **Purpose**: Main hero section with search functionality
- **Features**: Large background images, search forms, tag lists

### Content Sections
- **Locations**: `benefit/`, `services/`, `projects/`, `jobs/`
- **Purpose**: Showcase features, services, portfolios, or job listings
- **Features**: Cards, grids, swiper carousels

### Social Proof
- **Locations**: `testimonials/`, `brand/`, `counter/`
- **Purpose**: Build trust with testimonials, partner logos, statistics
- **Features**: Customer quotes, logo grids, animated counters

### Call-to-Action
- **Locations**: `banner/`, `download/`, `pricing/`
- **Purpose**: Drive user actions
- **Features**: CTA buttons, pricing tables, app download links

### Navigation & Discovery
- **Locations**: `categories/`, `explore/`, `faqs/`
- **Purpose**: Help users find content
- **Features**: Category grids, search interfaces, FAQ accordions

### Content Display
- **Locations**: `blog/`, `video/`, `freelancers/`
- **Purpose**: Display content and profiles
- **Features**: Article cards, video embeds, freelancer profiles

## Customization

To customize a component:

1. **Copy the component** to your working directory
2. **Modify content** (text, images, links)
3. **Keep classes intact** to maintain styling
4. **Test** to ensure asset paths work correctly

**Important**: Do NOT modify class names or HTML structure unless you also update the corresponding CSS.

## CSS Dependencies

These components require the following stylesheets (loaded in parent page):

```html
<link rel="stylesheet" href="./assets/css/swiper-bundle.min.css" />
<link rel="stylesheet" href="./assets/css/leaflet.css" />
<link rel="stylesheet" href="./assets/css/slick.css" />
<link rel="stylesheet" href="./assets/css/style.css" />
<link rel="stylesheet" href="./dist/output-tailwind.css" />
<link rel="stylesheet" href="./dist/output-scss.css" />
```

## JavaScript Dependencies

Some components (carousels, accordions, tabs) require JavaScript:

```html
<script src="./assets/js/swiper-bundle.min.js"></script>
<script src="./assets/js/main.js"></script>
```

Include these scripts at the end of your page body.

## Browser Compatibility

Components use modern CSS (Tailwind) and work with:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Best Practices

1. **Single Responsibility**: Each component handles one section type
2. **Consistent Naming**: Follow the naming convention for new components
3. **Path Management**: Always use relative paths adjusted for component location
4. **Version Control**: Track component changes separately from template files
5. **Testing**: Test components in actual page context before deployment
6. **Documentation**: Update this README when adding new component types

## Maintenance

### Adding New Components

1. Extract section from source file
2. Save to appropriate subdirectory
3. Follow naming convention
4. Adjust asset paths to `../../assets/`
5. Test independently
6. Update this README

### Updating Existing Components

1. Modify component file
2. Test in all pages using the component
3. Document breaking changes
4. Version appropriately (consider -v2 suffix for major changes)

## Component Index by Source File

| Source File | Components Extracted | Subdirectories |
|-------------|---------------------|----------------|
| freelancer2.html | 9-10 sections | slider, brand, services, categories, testimonials, benefit, blog, banner |
| freelancer3.html | 10-11 sections | slider, categories, benefit, services, freelancers, banner, counter, testimonials, blog, brand |
| freelancer4.html | 8-9 sections | slider, categories, benefit, services, freelancers, testimonials, blog |
| freelancer5.html | 11-13 sections | slider, categories, benefit (multiple), services, testimonials, projects, blog, banner, brand |
| freelancer6.html | 9-11 sections | slider, brand, categories, services, benefit, freelancers, testimonials, projects, blog, banner |
| freelancer7.html | 10-12 sections | slider, brand, services, video, benefit, projects, testimonials, freelancers, blog, download |
| freelancer8.html | 9-11 sections | slider, categories, services, benefit (multiple), projects, explore, faqs, banner |
| freelancer9.html | 8-10 sections | slider, services, benefit, freelancers, jobs, testimonials, blog, download |
| freelancer10.html | 9-11 sections | slider, jobs, benefit, freelancers, pricing, blog, download, brand, banner |
| freelancer11.html | 7-9 sections | slider, services, employers, jobs, testimonials, blog |
| freelancer12.html | 8-10 sections | slider, categories, jobs, benefit, employers, pricing, testimonials, banner |

## Support

For questions or issues with components:
1. Check this documentation first
2. Verify asset paths are correct
3. Ensure CSS/JS dependencies are loaded
4. Test component in isolation
5. Check browser console for errors

## License

These components are part of the FreelanHub project and subject to project licensing terms.

---

**Last Updated**: 2026-01-23
**Total Components**: 106 files
**Source Templates**: 11 files (freelancer2-12.html)
