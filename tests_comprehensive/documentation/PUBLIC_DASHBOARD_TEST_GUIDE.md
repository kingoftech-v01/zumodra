# Public User Dashboard Testing Guide

Complete guide for testing the NEW public user dashboard at **zumodra.rhematek-solutions.com**

---

## Overview

**Target Server:** https://zumodra.rhematek-solutions.com
**Dashboard URL:** https://zumodra.rhematek-solutions.com/app/dashboard/
**Template:** `templates/dashboard/public_user_dashboard.html`
**View Class:** `dashboard.template_views.DashboardView`

---

## What We're Testing

The newly created public user dashboard shows for users **without tenant membership**. It includes:

1. ✅ Welcome Banner (gradient blue to indigo)
2. ✅ MFA Warning Banner (for users without MFA)
3. ✅ Profile Completion Widget (with percentage and progress bar)
4. ✅ Quick Actions Cards (Browse Jobs, Services, Enable 2FA)
5. ✅ Recommended Jobs Section (max 5 jobs or empty state)
6. ✅ Join Organization CTA (purple gradient banner)
7. ✅ Dark Mode Support
8. ✅ Responsive Design (mobile, tablet, desktop)

---

## Test Files Created

### 1. Automated Django Tests
**File:** `test_public_user_dashboard.py`

```bash
# Run with pytest (requires Docker or GDAL)
docker compose exec web pytest test_public_user_dashboard.py -v --tb=short

# Or run locally (if GDAL is installed)
pytest test_public_user_dashboard.py -v --tb=short
```

**Tests:** 66+ automated test cases covering:
- Dashboard access and authentication
- All UI components
- Helper methods (_calculate_profile_completion, _get_recommended_jobs, _user_has_mfa)
- Dark mode classes
- Responsive design classes
- Context data

### 2. Manual HTTP Test Script
**File:** `test_public_dashboard_manual.py`

```bash
# Run the manual test script
python test_public_dashboard_manual.py
```

**Features:**
- Login via HTTP requests
- Test all major features
- Extract and validate content
- Save results to JSON

**Before running:**
- Update `TEST_USERS` dictionary with valid credentials
- Requires: `pip install requests`

### 3. Selenium Browser Automation
**File:** `test_public_dashboard_selenium.py`

```bash
# Install dependencies
pip install selenium webdriver-manager pillow

# Run Selenium tests
python test_public_dashboard_selenium.py
```

**Features:**
- Full browser automation with Chrome
- Takes screenshots of every section
- Tests hover effects and interactions
- Tests responsive design (mobile, tablet, desktop)
- Saves screenshots to `test_screenshots/` directory

**Before running:**
- Update `TEST_USER` dictionary with valid credentials
- Chrome browser must be installed

### 4. Comprehensive Test Checklist
**File:** `PUBLIC_USER_DASHBOARD_TEST_CHECKLIST.md`

**66-point manual test checklist** covering:
- Every UI element
- Every interaction
- Every helper method
- Performance, accessibility, integration

Use this for manual QA testing.

---

## Quick Start - 3 Ways to Test

### Option A: Automated Django Tests (Recommended)

```bash
# Start Docker services
cd c:\Users\techn\OneDrive\Documents\zumodra
docker compose up -d

# Run tests in container
docker compose exec web pytest test_public_user_dashboard.py -v

# View results
cat test_screenshots/test_results_*.json
```

### Option B: Selenium Browser Tests (Visual Testing)

```bash
# Install dependencies
pip install selenium webdriver-manager pillow

# Update credentials in test_public_dashboard_selenium.py
# Edit line 18-21 with valid test user

# Run tests
python test_public_dashboard_selenium.py

# View screenshots
# Open test_screenshots/ folder
```

### Option C: Manual Testing (Human QA)

1. Open browser
2. Navigate to https://zumodra.rhematek-solutions.com/accounts/login/
3. Login as public user (no tenant membership)
4. Navigate to https://zumodra.rhematek-solutions.com/app/dashboard/
5. Follow checklist in `PUBLIC_USER_DASHBOARD_TEST_CHECKLIST.md`
6. Document issues

---

## Test User Requirements

You need **4 types of test users**:

### User 1: Public User WITHOUT MFA
- ❌ No tenant membership
- ❌ MFA disabled
- ✅ Used to test MFA warning banner

### User 2: Public User WITH MFA
- ❌ No tenant membership
- ✅ MFA enabled
- ✅ Used to verify banner doesn't show

### User 3: Public User - Empty Profile
- ❌ No tenant membership
- ❌ Profile fields empty (no bio, phone, location, linkedin)
- ✅ Used to test 0% profile completion

### User 4: Public User - Complete Profile
- ❌ No tenant membership
- ✅ All profile fields filled (bio, phone, location, linkedin_url)
- ✅ Used to test 100% profile completion

---

## Expected Behavior

### For Public Users (No Tenant Membership)

✅ **SHOULD SEE:**
- Welcome banner with name
- MFA warning banner (if MFA not enabled)
- Profile completion widget
- Quick actions: Browse Jobs, Browse Services, Enable 2FA
- Recommended jobs (if available) or empty state
- Join Organization CTA

❌ **SHOULD NOT SEE:**
- Tenant-specific stats (open jobs, candidates, employees)
- Upcoming interviews
- Recent activity (from tenant)
- Tenant navigation/sidebar

### For Tenant Members

❌ **SHOULD NOT SEE public dashboard**
- Should see regular tenant dashboard (dashboard/index.html)
- Should see tenant-specific stats and widgets

---

## Testing Each Feature

### 1. Welcome Banner

**What to Check:**
- [ ] Displays "Welcome, [First Name]!"
- [ ] If no first name, shows username
- [ ] Gradient background (blue to indigo)
- [ ] White text
- [ ] "Complete your profile to unlock all features" message

**Screenshot:** Full-width banner at top

### 2. MFA Warning Banner

**For users WITHOUT MFA:**
- [ ] Yellow warning banner displays
- [ ] Shows "Security Notice:"
- [ ] Shows "Two-factor authentication will be required by [Date]"
- [ ] Date is 30 days from user.date_joined
- [ ] "Set it up now" link present
- [ ] Link goes to `/accounts/two-factor/` or MFA setup

**For users WITH MFA:**
- [ ] Banner does NOT display

**Screenshot:** Banner for user without MFA

### 3. Profile Completion Widget

**What to Check:**
- [ ] "Profile Completion" heading
- [ ] Percentage displays on right (0-100%)
- [ ] Progress bar shows correct width
- [ ] Blue progress fill (bg-blue-600)
- [ ] "Complete your profile →" link

**Test Different Scenarios:**
- Empty profile → 0%
- 1 field (bio) → 25%
- 2 fields (bio, phone) → 50%
- 3 fields (bio, phone, location) → 75%
- 4 fields (bio, phone, location, linkedin_url) → 100%

**Screenshot:** Widget at 0%, 50%, 100%

### 4. Quick Actions Cards

**What to Check:**
- [ ] 3 cards in grid layout
- [ ] Card 1: "Browse Jobs" (blue briefcase icon)
- [ ] Card 2: "Browse Services" (green storefront icon)
- [ ] Card 3: "Enable 2FA" (purple shield icon)
- [ ] Icons scale on hover (hover:scale-110)
- [ ] Shadow increases on hover (hover:shadow-lg)
- [ ] Grid: 1 column on mobile, 3 columns on desktop

**Test Links:**
- [ ] Browse Jobs → `/careers/`
- [ ] Browse Services → `/services/`
- [ ] Enable 2FA → `/accounts/two-factor/`

**Screenshot:** Cards on desktop, cards on mobile

### 5. Recommended Jobs Section

**If jobs available:**
- [ ] "Recommended Jobs" heading
- [ ] Maximum 5 jobs shown
- [ ] Each job shows: title, company, location, salary (if available)
- [ ] Location has map pin icon (ph-map-pin)
- [ ] Salary has currency icon (ph-currency-dollar)
- [ ] Job cards have hover effect (border-blue-500)
- [ ] "View all jobs →" link at bottom

**If no jobs available:**
- [ ] Empty state displays
- [ ] Large briefcase icon (gray)
- [ ] "No jobs available yet" heading
- [ ] "Check back soon" message
- [ ] "Browse all jobs" button (blue)

**Screenshot:** Jobs section or empty state

### 6. Join Organization CTA

**What to Check:**
- [ ] Purple to pink gradient background
- [ ] Team icon (ph-users-three) on left
- [ ] "Ready to do more?" heading
- [ ] Explanation text about organization features
- [ ] "Join Organization" button (white background, purple text)
- [ ] "Create Organization" button (purple background, white text)
- [ ] Both buttons have hover effects

**Screenshot:** Full CTA banner

### 7. Dark Mode

**How to Test:**
- Toggle dark mode (usually in header)
- Check all sections adapt correctly

**What to Check:**
- [ ] Page background: dark (gray-900)
- [ ] Cards: gray-800
- [ ] Text: white headings, gray-300 body
- [ ] Borders: gray-700
- [ ] Gradients still visible
- [ ] All icons visible
- [ ] Good contrast throughout

**Screenshot:** Full page in dark mode

### 8. Responsive Design

**Desktop (1920x1080):**
- [ ] Centered layout with max-width
- [ ] 3-column grid for quick actions
- [ ] All sections visible
- [ ] No horizontal scroll

**Tablet (768px):**
- [ ] 3-column grid maintained
- [ ] All sections visible
- [ ] Adequate spacing

**Mobile (375px):**
- [ ] Single column layout
- [ ] Cards stack vertically
- [ ] All text readable
- [ ] Buttons large enough to tap
- [ ] No horizontal scroll

**Screenshot:** Desktop, tablet, mobile views

---

## Common Issues to Watch For

### ❌ Potential Problems

1. **Template Not Used**
   - Symptom: Shows regular tenant dashboard instead
   - Cause: User has tenant membership
   - Fix: Use user without tenant membership

2. **MFA Banner Always Shows**
   - Symptom: Banner shows even with MFA enabled
   - Cause: _user_has_mfa() not working correctly
   - Check: User has active mfa_authenticators

3. **Profile Completion Always 0%**
   - Symptom: Shows 0% even with filled profile
   - Cause: UserProfile doesn't exist or fields not set
   - Check: user.userprofile exists and has bio, phone, location, linkedin_url

4. **No Jobs Display**
   - Symptom: Empty state always shows
   - Cause: No PublicJobCatalog entries
   - Fix: Create public jobs via admin or management command

5. **404 on Links**
   - Symptom: Clicking links gives 404
   - Cause: URL patterns not configured
   - Check: `/careers/`, `/services/`, `/accounts/two-factor/` exist

6. **Dark Mode Not Working**
   - Symptom: Toggle doesn't change appearance
   - Cause: JavaScript not loaded or classes not applied
   - Check: Browser console for errors

---

## Success Criteria

### ✅ Test PASSES if:

- [ ] All 66 test cases pass (or 90%+ pass rate)
- [ ] No critical bugs found
- [ ] All screenshots look correct
- [ ] Dark mode works properly
- [ ] Responsive design works on all screen sizes
- [ ] All links navigate correctly
- [ ] MFA banner shows/hides correctly based on user MFA status
- [ ] Profile completion calculates correctly
- [ ] Recommended jobs display (or empty state shows)
- [ ] Helper methods work without errors

### ❌ Test FAILS if:

- [ ] Template doesn't load
- [ ] Any section missing or broken
- [ ] MFA logic incorrect
- [ ] Profile completion wrong
- [ ] Broken links
- [ ] Poor mobile experience
- [ ] Dark mode broken
- [ ] Python exceptions in logs

---

## Reporting Results

### After Testing, Document:

1. **Summary Statistics**
   - Total tests: XX
   - Passed: XX
   - Failed: XX
   - Success rate: XX%

2. **Issues Found**
   For each issue:
   - **Title:** Brief description
   - **Severity:** Critical / High / Medium / Low
   - **Description:** What's wrong
   - **Steps to Reproduce:** How to see the issue
   - **Expected:** What should happen
   - **Actual:** What actually happens
   - **Screenshot:** Attach screenshot

3. **Screenshots**
   - Desktop view (full page)
   - Mobile view (full page)
   - Each section close-up
   - Dark mode view
   - Any issues found

4. **Browser Information**
   - Browser: Chrome/Firefox/Safari/Edge
   - Version: XX
   - OS: Windows/Mac/Linux
   - Screen resolution: XXXXxXXXX

---

## Next Steps After Testing

### If All Tests Pass ✅

1. Mark feature as complete
2. Deploy to production
3. Update documentation
4. Train support team

### If Tests Fail ❌

1. Document all issues
2. Prioritize by severity
3. Create bug tickets
4. Fix critical issues first
5. Re-test after fixes

---

## Additional Resources

- **Template:** `c:\Users\techn\OneDrive\Documents\zumodra\templates\dashboard\public_user_dashboard.html`
- **View:** `c:\Users\techn\OneDrive\Documents\zumodra\dashboard\template_views.py` (line 27-217)
- **URL:** Mapped to `/app/dashboard/` in `dashboard/urls.py`
- **CLAUDE.md:** Project documentation with URL namespaces

---

## Contact

For questions about this testing:
- Review CLAUDE.md for project conventions
- Check template_views.py for implementation details
- See PUBLIC_USER_DASHBOARD_TEST_CHECKLIST.md for detailed test cases

---

**Last Updated:** 2026-01-16
**Template Version:** 1.0.0
**Test Suite Version:** 1.0.0
