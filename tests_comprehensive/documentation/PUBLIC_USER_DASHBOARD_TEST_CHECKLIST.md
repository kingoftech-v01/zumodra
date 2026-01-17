# Public User Dashboard Test Checklist

**Target Server:** https://zumodra.rhematek-solutions.com
**Dashboard URL:** https://zumodra.rhematek-solutions.com/app/dashboard/
**Template:** `templates/dashboard/public_user_dashboard.html`
**View:** `dashboard.template_views.DashboardView`

---

## Test Users Required

| User Type | Requirements | Purpose |
|-----------|-------------|---------|
| Public User (No MFA) | No tenant membership, MFA disabled | Test MFA warning banner |
| Public User (With MFA) | No tenant membership, MFA enabled | Verify banner doesn't show |
| Public User (Complete Profile) | All profile fields filled | Test 100% completion |
| Public User (Partial Profile) | Some profile fields filled | Test partial completion |

---

## 1. Dashboard Access Tests

### Test 1.1: Authentication Required
- [ ] Anonymous user redirected to login page
- [ ] Login page loads at `/accounts/login/`
- [ ] After login, redirected to dashboard

### Test 1.2: Template Loading
- [ ] Dashboard loads without errors (HTTP 200)
- [ ] Correct template used: `public_user_dashboard.html`
- [ ] No Python exceptions in page source
- [ ] No 404 or 500 errors

### Test 1.3: Page Rendering
- [ ] Page renders completely
- [ ] No broken layouts
- [ ] No missing content sections
- [ ] All CSS loads correctly

**Screenshot:** Take full-page screenshot of loaded dashboard

---

## 2. Welcome Banner Tests

### Test 2.1: Display
- [ ] Welcome banner visible at top of page
- [ ] Banner shows "Welcome, [First Name]!"
- [ ] If no first name, shows username instead
- [ ] Banner text is readable

### Test 2.2: Styling
- [ ] Gradient background: blue to indigo
- [ ] Text color: white
- [ ] Rounded corners visible
- [ ] Shadow effect present
- [ ] Padding adequate (not cramped)

### Test 2.3: Content
- [ ] "Complete your profile to unlock all features" message displays
- [ ] Message color: light blue (text-blue-100)

**Screenshot:** Close-up of welcome banner

---

## 3. MFA Warning Banner Tests

### Test 3.1: Display (User WITHOUT MFA)
- [ ] Yellow warning banner displays
- [ ] Banner positioned below welcome banner
- [ ] Border-left accent (yellow, 4px)
- [ ] Shield warning icon displays
- [ ] Icon color: yellow (text-yellow-400)

### Test 3.2: Content (User WITHOUT MFA)
- [ ] "Security Notice:" label in bold
- [ ] "Two-factor authentication will be required by [Date]" message
- [ ] Date shows 30 days from signup (e.g., "February 15, 2026")
- [ ] Date format: Month Day, Year
- [ ] "Set it up now" link displays
- [ ] Link is underlined
- [ ] Link hover effect works

### Test 3.3: Link Functionality (User WITHOUT MFA)
- [ ] "Set it up now" link navigates to `/accounts/two-factor/` or MFA setup page
- [ ] Link opens in same tab
- [ ] No JavaScript errors on click

### Test 3.4: Hidden State (User WITH MFA)
- [ ] Banner does NOT display for users with MFA enabled
- [ ] No yellow warning section visible
- [ ] No "Security Notice" text

### Test 3.5: Dark Mode
- [ ] Dark mode background: `dark:bg-yellow-900/20`
- [ ] Dark mode text: `dark:text-yellow-300`
- [ ] Dark mode hover: `dark:hover:text-yellow-100`

**Screenshots:**
- MFA warning banner (user without MFA)
- Dashboard without MFA banner (user with MFA)
- MFA banner in dark mode

---

## 4. Profile Completion Widget Tests

### Test 4.1: Display
- [ ] Widget visible in white card
- [ ] Card has shadow
- [ ] Card has rounded corners
- [ ] "Profile Completion" heading displays

### Test 4.2: Percentage Display
- [ ] Percentage number shows on right side
- [ ] Number is large (text-2xl) and bold
- [ ] Number color: blue (text-blue-600)
- [ ] Percentage ranges 0-100%

### Test 4.3: Progress Bar
- [ ] Progress bar container visible (gray background)
- [ ] Progress bar container: full width, rounded
- [ ] Progress fill: blue (bg-blue-600)
- [ ] Progress fill width matches percentage
- [ ] Progress fill: rounded, smooth transition

### Test 4.4: Calculation (Empty Profile)
- [ ] User with no profile fields: 0%
- [ ] Calculation includes: bio, phone, location, linkedin_url
- [ ] 0 fields filled = 0%

### Test 4.5: Calculation (Partial Profile)
- [ ] User with 1 field: 25%
- [ ] User with 2 fields: 50%
- [ ] User with 3 fields: 75%

### Test 4.6: Calculation (Complete Profile)
- [ ] User with all 4 fields: 100%
- [ ] Progress bar full width
- [ ] Percentage shows "100%"

### Test 4.7: Link
- [ ] "Complete your profile →" link displays
- [ ] Link color: blue
- [ ] Link hover effect works (darker blue)
- [ ] Link navigates to profile page
- [ ] Arrow symbol (→) displays

### Test 4.8: Dark Mode
- [ ] Dark mode card background: gray-800
- [ ] Dark mode heading: white
- [ ] Dark mode progress container: gray-700

**Screenshots:**
- Profile completion at 0%
- Profile completion at 50%
- Profile completion at 100%
- Dark mode profile widget

---

## 5. Quick Actions Cards Tests

### Test 5.1: Display
- [ ] Three cards display in grid
- [ ] Grid layout: 1 column on mobile, 3 columns on desktop
- [ ] All cards same height
- [ ] Cards have white background
- [ ] Cards have shadow
- [ ] Cards have rounded corners

### Test 5.2: Card 1 - Browse Jobs
- [ ] Blue briefcase icon (ph-briefcase)
- [ ] Icon size: 3xl
- [ ] Icon color: blue-600
- [ ] Heading: "Browse Jobs"
- [ ] Subtext: "Find your next opportunity"
- [ ] Link points to `/careers/`

### Test 5.3: Card 2 - Browse Services
- [ ] Green storefront icon (ph-storefront)
- [ ] Icon size: 3xl
- [ ] Icon color: green-600
- [ ] Heading: "Browse Services"
- [ ] Subtext: "Discover freelance services"
- [ ] Link points to `/services/`

### Test 5.4: Card 3 - Enable 2FA
- [ ] Purple shield icon (ph-shield-check)
- [ ] Icon size: 3xl
- [ ] Icon color: purple-600
- [ ] Heading: "Enable 2FA"
- [ ] Subtext: "Secure your account"
- [ ] Link points to MFA setup page

### Test 5.5: Hover Effects
- [ ] Card shadow increases on hover (hover:shadow-lg)
- [ ] Icon scales up on hover (scale-110)
- [ ] Transition is smooth
- [ ] All 3 cards have hover effect

### Test 5.6: Responsive Layout
- [ ] Mobile (375px): Cards stack vertically (1 column)
- [ ] Tablet (768px): Cards in 3 columns
- [ ] Desktop (1920px): Cards in 3 columns with gaps

### Test 5.7: Dark Mode
- [ ] Dark mode card background: gray-800
- [ ] Dark mode heading: white
- [ ] Dark mode subtext: gray-400

**Screenshots:**
- Quick actions grid (desktop)
- Quick actions stacked (mobile)
- Hover state on one card
- Dark mode quick actions

---

## 6. Recommended Jobs Section Tests

### Test 6.1: Display (Jobs Available)
- [ ] "Recommended Jobs" heading displays
- [ ] Section in white card with shadow
- [ ] Heading is bold, large
- [ ] Maximum 5 jobs shown
- [ ] Jobs ordered by creation date (newest first)

### Test 6.2: Job Card Content
- [ ] Job title displays (bold, large)
- [ ] Company name displays (smaller, gray)
- [ ] Location displays with map pin icon (ph-map-pin)
- [ ] Salary displays if available ($XX,XXX - $XX,XXX)
- [ ] Currency icon (ph-currency-dollar) before salary

### Test 6.3: Job Card Styling
- [ ] Each job in bordered container
- [ ] Border: gray-200 by default
- [ ] Border: blue-500 on hover
- [ ] Padding inside card
- [ ] Rounded corners
- [ ] Hover transition smooth

### Test 6.4: Job Links
- [ ] Each job card is clickable
- [ ] Links point to `/careers/jobs/[job_id]/`
- [ ] Links open in same tab
- [ ] No broken links

### Test 6.5: View All Jobs Link
- [ ] "View all jobs →" link at bottom
- [ ] Link color: blue
- [ ] Link hover effect works
- [ ] Link points to `/careers/`
- [ ] Arrow symbol (→) displays

### Test 6.6: Empty State (No Jobs)
- [ ] Empty state displays when no jobs available
- [ ] Large briefcase icon (ph-briefcase, text-6xl)
- [ ] Icon color: gray-300
- [ ] "No jobs available yet" heading
- [ ] "Check back soon" message
- [ ] "Browse all jobs" button displays
- [ ] Button color: blue background, white text
- [ ] Button hover effect works

### Test 6.7: Dark Mode
- [ ] Dark mode section background: gray-800
- [ ] Dark mode heading: white
- [ ] Dark mode job title: white
- [ ] Dark mode company/location: gray-400
- [ ] Dark mode borders: gray-700
- [ ] Dark mode empty state icon: gray-600

**Screenshots:**
- Recommended jobs section (5 jobs)
- Job card hover state
- Empty state (no jobs)
- Dark mode jobs section

---

## 7. Join Organization CTA Tests

### Test 7.1: Display
- [ ] CTA banner displays at bottom
- [ ] Banner visible (show_tenant_invite = True)
- [ ] Banner has gradient background: purple to pink
- [ ] Banner has shadow
- [ ] Banner has rounded corners

### Test 7.2: Icon
- [ ] Team/users icon displays (ph-users-three)
- [ ] Icon size: 4xl
- [ ] Icon color: white
- [ ] Icon on left side

### Test 7.3: Content
- [ ] Heading: "Ready to do more?"
- [ ] Heading is bold, large
- [ ] Explanation text displays
- [ ] Text mentions: "Join an organization to access advanced features"
- [ ] Text mentions features: "applicant tracking, team management, and more"
- [ ] Text color: light purple (text-purple-100)

### Test 7.4: Buttons
- [ ] Two buttons display side-by-side
- [ ] Button 1: "Join Organization"
  - [ ] White background
  - [ ] Purple text (text-purple-600)
  - [ ] Hover: gray background
- [ ] Button 2: "Create Organization"
  - [ ] Purple background (bg-purple-700)
  - [ ] White text
  - [ ] Hover: darker purple (bg-purple-800)
- [ ] Both buttons have rounded corners
- [ ] Both buttons have padding
- [ ] Buttons have gap between them

### Test 7.5: Responsive Layout
- [ ] Desktop: Icon and content side-by-side
- [ ] Mobile: Icon and content stack vertically
- [ ] Buttons stay horizontal on mobile

### Test 7.6: Dark Mode
- [ ] Gradient still visible in dark mode
- [ ] Text readable in dark mode
- [ ] Buttons visible in dark mode

**Screenshots:**
- Join organization CTA (desktop)
- Join organization CTA (mobile)
- Button hover states

---

## 8. Dark Mode Tests

### Test 8.1: Toggle Dark Mode
- [ ] Dark mode toggle button accessible
- [ ] Toggle located in header/nav
- [ ] Toggle has sun/moon icon
- [ ] Click toggles dark mode

### Test 8.2: Background Colors
- [ ] Page background: dark (gray-900 or similar)
- [ ] Card backgrounds: gray-800
- [ ] Containers adapt to dark mode

### Test 8.3: Text Colors
- [ ] Headings: white (dark:text-white)
- [ ] Body text: light gray (dark:text-gray-300)
- [ ] Muted text: darker gray (dark:text-gray-400)
- [ ] Links: lighter blue (dark:text-blue-400)

### Test 8.4: Borders
- [ ] Borders visible in dark mode (gray-700)
- [ ] Border contrast adequate
- [ ] No invisible borders

### Test 8.5: Gradients
- [ ] Welcome banner gradient still visible
- [ ] Join org banner gradient still visible
- [ ] Gradients have good contrast

### Test 8.6: Icons
- [ ] All icons visible in dark mode
- [ ] Icon colors adapt (if needed)
- [ ] No invisible icons

### Test 8.7: Hover States
- [ ] Hover effects visible in dark mode
- [ ] Hover colors have adequate contrast
- [ ] No invisible hover states

**Screenshots:**
- Full dashboard in dark mode
- Each section in dark mode (close-ups)

---

## 9. Responsive Design Tests

### Test 9.1: Desktop (1920x1080)
- [ ] Layout centered with max-width
- [ ] All sections visible
- [ ] No horizontal scroll
- [ ] Adequate whitespace
- [ ] Grid: 3 columns for quick actions
- [ ] All text readable

### Test 9.2: Laptop (1366x768)
- [ ] Layout adapts correctly
- [ ] No horizontal scroll
- [ ] All sections visible
- [ ] Grid: 3 columns

### Test 9.3: Tablet (768x1024)
- [ ] Layout responsive
- [ ] Grid: 3 columns (breakpoint at md:)
- [ ] All text readable
- [ ] No horizontal scroll
- [ ] Touch targets adequate size

### Test 9.4: Mobile (375x667)
- [ ] Layout stacks vertically
- [ ] Grid: 1 column
- [ ] All sections visible
- [ ] No horizontal scroll
- [ ] Text readable (not too small)
- [ ] Buttons large enough to tap
- [ ] No overlapping content

### Test 9.5: Mobile (320x568 - Small)
- [ ] Layout still functional
- [ ] All content accessible
- [ ] No broken layouts

**Screenshots:**
- Desktop view (1920px)
- Tablet view (768px)
- Mobile view (375px)
- Small mobile view (320px)

---

## 10. Helper Methods Tests

### Test 10.1: _calculate_profile_completion()
- [ ] Method works without errors
- [ ] Returns integer 0-100
- [ ] Checks 4 fields: bio, phone, location, linkedin_url
- [ ] 0 fields = 0%
- [ ] 1 field = 25%
- [ ] 2 fields = 50%
- [ ] 3 fields = 75%
- [ ] 4 fields = 100%
- [ ] Handles missing UserProfile gracefully

### Test 10.2: _get_recommended_jobs()
- [ ] Returns PublicJobCatalog queryset
- [ ] Only returns active jobs (is_active=True)
- [ ] Orders by created_at descending (newest first)
- [ ] Returns empty queryset if no jobs
- [ ] Handles database errors gracefully

### Test 10.3: _user_has_mfa()
- [ ] Returns boolean (True/False)
- [ ] Checks for active MFA authenticators
- [ ] Returns False if no MFA
- [ ] Returns True if MFA enabled
- [ ] Handles missing mfa_authenticators attribute

---

## 11. Performance Tests

### Test 11.1: Page Load Time
- [ ] Dashboard loads in < 2 seconds
- [ ] No slow database queries
- [ ] No N+1 query problems

### Test 11.2: Asset Loading
- [ ] All CSS loads
- [ ] All JS loads
- [ ] All icons load
- [ ] No 404 errors in console

### Test 11.3: Browser Console
- [ ] No JavaScript errors
- [ ] No console warnings
- [ ] No failed network requests

---

## 12. Accessibility Tests

### Test 12.1: Semantic HTML
- [ ] Proper heading hierarchy (h1, h2, h3)
- [ ] Links have descriptive text
- [ ] Buttons have clear labels

### Test 12.2: Keyboard Navigation
- [ ] Tab through all interactive elements
- [ ] Focus indicators visible
- [ ] Enter/Space activates links/buttons
- [ ] No keyboard traps

### Test 12.3: Screen Reader
- [ ] Headings announced correctly
- [ ] Links announced with context
- [ ] Icon text alternatives present (if needed)

### Test 12.4: Color Contrast
- [ ] Text has sufficient contrast
- [ ] Links distinguishable from text
- [ ] Dark mode has adequate contrast

---

## 13. Integration Tests

### Test 13.1: Navigation
- [ ] Header navigation works
- [ ] Footer navigation works
- [ ] All internal links work
- [ ] No broken links

### Test 13.2: Profile Link
- [ ] "Complete your profile" link navigates to profile page
- [ ] Profile page loads correctly
- [ ] Back button returns to dashboard

### Test 13.3: Careers Link
- [ ] "Browse Jobs" card navigates to `/careers/`
- [ ] "View all jobs" link works
- [ ] Job detail links work

### Test 13.4: Services Link
- [ ] "Browse Services" card navigates to `/services/`
- [ ] Services page loads correctly

### Test 13.5: MFA Link
- [ ] "Set it up now" link navigates to MFA setup
- [ ] "Enable 2FA" card navigates to MFA setup
- [ ] MFA setup page loads correctly

---

## Test Summary Template

| Category | Tests | Passed | Failed | Notes |
|----------|-------|--------|--------|-------|
| Dashboard Access | 3 | | | |
| Welcome Banner | 3 | | | |
| MFA Warning | 5 | | | |
| Profile Completion | 8 | | | |
| Quick Actions | 7 | | | |
| Recommended Jobs | 7 | | | |
| Join Organization CTA | 6 | | | |
| Dark Mode | 7 | | | |
| Responsive Design | 5 | | | |
| Helper Methods | 3 | | | |
| Performance | 3 | | | |
| Accessibility | 4 | | | |
| Integration | 5 | | | |
| **TOTAL** | **66** | | | |

---

## Issues Found

Document any issues here:

1. **Issue Title**
   - **Severity:** Critical / High / Medium / Low
   - **Description:**
   - **Steps to Reproduce:**
   - **Expected Behavior:**
   - **Actual Behavior:**
   - **Screenshot:** (attach)

---

## Test Environment

- **Server:** zumodra.rhematek-solutions.com
- **Date:** [Test Date]
- **Tester:** [Your Name]
- **Browser:** Chrome / Firefox / Safari / Edge
- **Browser Version:**
- **OS:** Windows / macOS / Linux
- **Screen Resolution:**

---

## Sign-Off

- [ ] All critical tests passed
- [ ] All issues documented
- [ ] Screenshots attached
- [ ] Ready for production

**Tester Signature:** _________________________
**Date:** _________________________
