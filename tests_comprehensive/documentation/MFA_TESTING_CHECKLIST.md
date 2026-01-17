# Two-Factor Authentication (MFA) Testing Checklist

**Server:** zumodra.rhematek-solutions.com
**Date:** 2026-01-16
**Tester:** _____________
**Purpose:** Verify MFA setup, enforcement, and 30-day grace period functionality

---

## 📋 Pre-Test Setup

- [ ] Access to production server: https://zumodra.rhematek-solutions.com
- [ ] Test user account credentials available
- [ ] Google Authenticator or Authy app installed on mobile device
- [ ] Screenshot tool ready (browser dev tools, Snipping Tool, etc.)
- [ ] Browser cache cleared before testing

---

## Test 1: MFA Setup Page Access ✅/❌

**Objective:** Verify MFA setup page loads correctly and shows available methods.

### Steps:

1. **Unauthenticated Access Test**
   - [ ] Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/two-factor/`
   - [ ] **Expected:** Redirected to login page
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test1_1_unauth_redirect.png`

2. **Authenticated Access Test**
   - [ ] Login with test credentials
   - [ ] Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/two-factor/`
   - [ ] **Expected:** MFA setup page loads (HTTP 200)
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test1_2_mfa_setup_page.png`

3. **Available MFA Methods**
   - [ ] Check for "Authenticator App" or "TOTP" option
   - [ ] **Found:** ✅/❌
   - [ ] Check for "WebAuthn" or "Security Key" option
   - [ ] **Found:** ✅/❌
   - [ ] Screenshot saved as: `test1_3_mfa_methods.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 2: TOTP Setup Flow ✅/❌

**Objective:** Verify TOTP/Authenticator app setup works correctly.

### Steps:

1. **Enable Authenticator App**
   - [ ] Click "Enable Authenticator App" button
   - [ ] **Expected:** Redirected to TOTP activation page
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test2_1_totp_activate.png`

2. **QR Code Generation**
   - [ ] Verify QR code displays correctly
   - [ ] **QR Code Visible:** ✅/❌
   - [ ] Screenshot saved as: `test2_2_qr_code.png`

3. **Manual Entry Secret**
   - [ ] Locate manual entry secret (usually 32-character base32 string)
   - [ ] **Secret Found:** ✅/❌
   - [ ] **Secret (first 10 chars):** _______________
   - [ ] Screenshot saved as: `test2_3_manual_secret.png`

4. **Scan QR Code**
   - [ ] Open Google Authenticator or Authy on mobile device
   - [ ] Scan QR code
   - [ ] **Expected:** "Zumodra" or account email appears in app
   - [ ] **Actual:** _______________
   - [ ] Screenshot of authenticator app: `test2_4_auth_app.png`

5. **Enter Verification Code**
   - [ ] Get 6-digit code from authenticator app
   - [ ] Enter code in verification field
   - [ ] Submit form
   - [ ] **Expected:** Success message "TOTP activated successfully"
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test2_5_totp_activated.png`

6. **Verify TOTP Status**
   - [ ] Navigate back to `/en-us/accounts/two-factor/`
   - [ ] **Expected:** TOTP shows as "Active" or "Enabled"
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test2_6_totp_status.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 3: MFA Challenge on Login ✅/❌

**Objective:** Verify MFA challenge appears after login for users with MFA enabled.

### Steps:

1. **Logout**
   - [ ] Click logout from user dropdown
   - [ ] **Expected:** Redirected to login page
   - [ ] **Actual:** _______________

2. **Login with Username/Password**
   - [ ] Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/login/`
   - [ ] Enter email and password
   - [ ] Submit login form
   - [ ] **Expected:** Redirected to MFA challenge page (not dashboard)
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test3_1_mfa_challenge.png`

3. **Enter TOTP Code**
   - [ ] Get fresh 6-digit code from authenticator app
   - [ ] Enter code in MFA challenge field
   - [ ] Submit form
   - [ ] **Expected:** Successfully logged in, redirected to dashboard
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test3_2_mfa_success.png`

4. **Test Invalid Code**
   - [ ] Logout and login again
   - [ ] Enter wrong 6-digit code (e.g., "000000")
   - [ ] **Expected:** Error message "Invalid code"
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test3_3_invalid_code.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 4: 30-Day Grace Period Enforcement ✅/❌

**Objective:** Verify new users get 30-day grace period before MFA is required.

### Steps:

1. **Create New Test User**
   - [ ] Create brand new user account (if possible)
   - [ ] **User Email:** _______________
   - [ ] **Account Created:** _______________

2. **Login as New User (No MFA)**
   - [ ] Login with new user credentials
   - [ ] **Expected:** Login succeeds WITHOUT MFA challenge
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test4_1_new_user_login.png`

3. **Check Dashboard for Reminder**
   - [ ] Navigate to dashboard: `/en-us/app/dashboard/`
   - [ ] Look for MFA setup reminder banner/message
   - [ ] **Reminder Found:** ✅/❌
   - [ ] **Message Text:** _______________
   - [ ] Screenshot saved as: `test4_2_grace_reminder.png`

4. **Verify No Forced Redirect**
   - [ ] Try accessing protected pages (e.g., `/en-us/app/dashboard/`, `/en-us/app/ats/jobs/`)
   - [ ] **Expected:** Access granted (no redirect to MFA setup)
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test4_3_no_forced_redirect.png`

5. **Check Reminder 7 Days Before Deadline**
   - [ ] Check if reminder appears 7 days before 30-day deadline
   - [ ] **Note:** This requires user account 23+ days old
   - [ ] **Manual Test Required:** ✅/❌

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 5: MFA Enforcement After 30 Days ✅/❌

**Objective:** Verify users older than 30 days are forced to set up MFA.

### Steps:

1. **Use Old User Account**
   - [ ] Login as user created > 30 days ago
   - [ ] **User Email:** _______________
   - [ ] **Account Age:** _____ days

2. **Check for Forced Redirect**
   - [ ] After login, check URL
   - [ ] **Expected:** Redirected to `/en-us/accounts/two-factor/` (MFA setup)
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test5_1_forced_redirect.png`

3. **Verify Warning Message**
   - [ ] Check for warning message explaining MFA requirement
   - [ ] **Message Found:** ✅/❌
   - [ ] **Message Text:** _______________
   - [ ] Screenshot saved as: `test5_2_warning_message.png`

4. **Test Protected Pages Blocked**
   - [ ] Try to navigate directly to `/en-us/app/dashboard/`
   - [ ] **Expected:** Redirected back to MFA setup page
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test5_3_blocked_access.png`

5. **Verify Exempt Paths Work**
   - [ ] Try accessing `/en-us/accounts/logout/` (should work)
   - [ ] **Expected:** Logout succeeds without MFA setup
   - [ ] **Actual:** _______________
   - [ ] Try accessing `/static/css/style.css` (should work)
   - [ ] **Expected:** Static files load normally
   - [ ] **Actual:** _______________

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 6: Navigation Integration ✅/❌

**Objective:** Verify MFA link is accessible from navigation menus.

### Steps:

1. **Check User Dropdown Menu**
   - [ ] Login as authenticated user
   - [ ] Open user dropdown menu (usually top-right corner)
   - [ ] Look for "Two-Factor Auth" or "MFA" link
   - [ ] **Link Found:** ✅/❌
   - [ ] Screenshot saved as: `test6_1_user_dropdown.png`

2. **Check Setup Badge**
   - [ ] If MFA not enabled, check for "Setup" badge next to MFA link
   - [ ] **Badge Found:** ✅/❌
   - [ ] Screenshot saved as: `test6_2_setup_badge.png`

3. **Test MFA Link Navigation**
   - [ ] Click "Two-Factor Auth" link
   - [ ] **Expected:** Navigates to `/en-us/accounts/two-factor/`
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test6_3_mfa_link_nav.png`

4. **Check Settings Page**
   - [ ] Navigate to user settings/profile page
   - [ ] Check if MFA option appears in settings
   - [ ] **Found in Settings:** ✅/❌
   - [ ] Screenshot saved as: `test6_4_settings_mfa.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 7: Backup Codes ✅/❌

**Objective:** Verify backup codes generation and usage.

### Steps:

1. **Generate Backup Codes**
   - [ ] Navigate to `/en-us/accounts/two-factor/recovery-codes/`
   - [ ] Click "Generate Backup Codes" button
   - [ ] **Expected:** List of 8-10 backup codes displayed
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test7_1_backup_codes.png`
   - [ ] **Sample Code (for verification):** _______________

2. **Download/Save Codes**
   - [ ] Check if "Download" or "Print" option available
   - [ ] **Option Available:** ✅/❌
   - [ ] Save codes securely

3. **Test Login with Backup Code**
   - [ ] Logout
   - [ ] Login with username/password
   - [ ] At MFA challenge, use "Use backup code" option
   - [ ] **Option Found:** ✅/❌
   - [ ] Enter one backup code
   - [ ] **Expected:** Login succeeds
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test7_2_backup_login.png`

4. **Verify Code Invalidation**
   - [ ] Try to reuse the same backup code
   - [ ] **Expected:** Error message "Code already used"
   - [ ] **Actual:** _______________
   - [ ] Screenshot saved as: `test7_3_code_invalidated.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Test 8: Middleware Functionality ✅/❌

**Objective:** Verify MFAEnforcementMiddleware works correctly.

### Steps:

1. **Test Exempt Paths**
   - [ ] Access `/en-us/accounts/two-factor/` (should be exempt)
   - [ ] **No redirect loop:** ✅/❌
   - [ ] Access `/en-us/accounts/logout/` (should be exempt)
   - [ ] **Works correctly:** ✅/❌
   - [ ] Access `/static/css/style.css` (should be exempt)
   - [ ] **Works correctly:** ✅/❌
   - [ ] Access `/api/health/` (should be exempt)
   - [ ] **Works correctly:** ✅/❌

2. **Test Protected Paths**
   - [ ] Access `/en-us/app/dashboard/` without MFA (as old user)
   - [ ] **Expected:** Redirected to MFA setup
   - [ ] **Actual:** _______________

3. **Check for Redirect Loops**
   - [ ] Monitor browser console for repeated redirects
   - [ ] **No redirect loops detected:** ✅/❌
   - [ ] Screenshot saved as: `test8_1_no_loops.png`

4. **Verify Session Key**
   - [ ] Open browser DevTools > Application > Cookies
   - [ ] Look for `mfa_reminder_shown_{user_id}` session key
   - [ ] **Session key found:** ✅/❌
   - [ ] Refresh page
   - [ ] **Expected:** Reminder shown only once per session
   - [ ] **Actual:** _______________

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _______________

---

## Summary & Overall Results

### Test Results Overview

| Test | Status | Notes |
|------|--------|-------|
| 1. MFA Setup Page Access | ✅/❌ | |
| 2. TOTP Setup Flow | ✅/❌ | |
| 3. MFA Challenge on Login | ✅/❌ | |
| 4. 30-Day Grace Period | ✅/❌ | |
| 5. MFA Enforcement (>30 days) | ✅/❌ | |
| 6. Navigation Integration | ✅/❌ | |
| 7. Backup Codes | ✅/❌ | |
| 8. Middleware Functionality | ✅/❌ | |

**Total Tests:** 8
**Passed:** ___
**Failed:** ___

### Critical Issues Found

1. _______________
2. _______________
3. _______________

### Non-Critical Issues Found

1. _______________
2. _______________
3. _______________

### Recommendations

1. _______________
2. _______________
3. _______________

---

## Screenshots Index

**Save all screenshots in a folder named:** `MFA_Test_Screenshots_YYYYMMDD`

### Test 1 Screenshots:
- `test1_1_unauth_redirect.png` - Unauthenticated redirect
- `test1_2_mfa_setup_page.png` - MFA setup page
- `test1_3_mfa_methods.png` - Available MFA methods

### Test 2 Screenshots:
- `test2_1_totp_activate.png` - TOTP activation page
- `test2_2_qr_code.png` - QR code display
- `test2_3_manual_secret.png` - Manual entry secret
- `test2_4_auth_app.png` - Authenticator app (mobile)
- `test2_5_totp_activated.png` - TOTP activation success
- `test2_6_totp_status.png` - TOTP status verification

### Test 3 Screenshots:
- `test3_1_mfa_challenge.png` - MFA challenge screen
- `test3_2_mfa_success.png` - MFA login success
- `test3_3_invalid_code.png` - Invalid code error

### Test 4 Screenshots:
- `test4_1_new_user_login.png` - New user login (no MFA)
- `test4_2_grace_reminder.png` - Grace period reminder
- `test4_3_no_forced_redirect.png` - No forced redirect

### Test 5 Screenshots:
- `test5_1_forced_redirect.png` - Forced redirect to MFA setup
- `test5_2_warning_message.png` - MFA requirement warning
- `test5_3_blocked_access.png` - Protected pages blocked

### Test 6 Screenshots:
- `test6_1_user_dropdown.png` - User dropdown menu
- `test6_2_setup_badge.png` - Setup badge
- `test6_3_mfa_link_nav.png` - MFA link navigation
- `test6_4_settings_mfa.png` - MFA in settings

### Test 7 Screenshots:
- `test7_1_backup_codes.png` - Backup codes display
- `test7_2_backup_login.png` - Login with backup code
- `test7_3_code_invalidated.png` - Code invalidation error

### Test 8 Screenshots:
- `test8_1_no_loops.png` - No redirect loops

---

## Additional Notes

**Testing Environment:**
- Browser: _______________
- Browser Version: _______________
- Operating System: _______________
- Screen Resolution: _______________
- Network: _______________

**Test Duration:** _____
**Tester Name:** _____
**Tester Email:** _____
**Test Date:** _____

**Sign-off:**
- [ ] All critical tests passed
- [ ] No redirect loops detected
- [ ] MFA middleware working correctly
- [ ] Documentation updated

---

## Appendix: Known Issues & Expected Behavior

### MFA Grace Period Behavior
- **First 30 days:** Users can access platform without MFA
- **Days 23-30:** Reminder message appears on dashboard
- **After 30 days:** Users redirected to MFA setup on every login

### Exempt Paths (No MFA Required)
- `/accounts/two-factor/*` - MFA setup pages
- `/accounts/logout/` - Logout endpoint
- `/static/*` - Static files
- `/media/*` - Media files
- `/api/*` - API endpoints (use JWT instead)
- `/health/*` - Health check endpoints

### Superuser Exemption
- Superusers are exempt from MFA enforcement
- This allows emergency admin access

### Session Management
- MFA reminder shown once per session
- Session key: `mfa_reminder_shown_{user_id}`
- Reminder resets after logout

---

**End of Checklist**
