# Execute MFA Tests - Step-by-Step Guide

**Target Server:** https://zumodra.rhematek-solutions.com
**Test Date:** 2026-01-16
**Middleware:** MFAEnforcementMiddleware (30-day grace period)

---

## 🎯 Mission Briefing

You are testing the **NEW** MFAEnforcementMiddleware that was just deployed to production. This middleware enforces Two-Factor Authentication (MFA) after a 30-day grace period for new users.

**Critical Questions to Answer:**
1. Does the MFA setup page load correctly?
2. Can users set up TOTP with authenticator apps?
3. Does the MFA challenge work on login?
4. Are new users allowed 30 days grace period?
5. Are old users (>30 days) redirected to MFA setup?
6. Is the navigation integrated with MFA links?
7. Do backup codes work?
8. Are there any redirect loops?

---

## 📦 Prerequisites

Before starting, ensure you have:

- [ ] Access to https://zumodra.rhematek-solutions.com
- [ ] Test user credentials (or ability to create new accounts)
- [ ] Mobile device with Google Authenticator, Authy, or Microsoft Authenticator
- [ ] Screenshot tool (browser built-in, Snipping Tool, etc.)
- [ ] 30-45 minutes of uninterrupted time
- [ ] This guide printed or on second screen

---

## 🚀 Quick Start (Automated Tests First)

### Option 1: Run Automated Test Script

```bash
# Navigate to project directory
cd c:\Users\techn\OneDrive\Documents\zumodra

# Run automated tests
python test_mfa_enforcement.py
```

**Expected Output:**
```
================================================================================
MFA ENFORCEMENT TEST SUITE
================================================================================
Target Server: https://zumodra.rhematek-solutions.com
Test Date: 2026-01-16 17:30:00
================================================================================

✅ 1.1 Unauthenticated Access: PASS
   Correctly redirected to login (HTTP 302)

✅ 1.2 Authenticated Access: PASS
   MFA setup page loads successfully

...

================================================================================
TEST SUMMARY
================================================================================
Total Tests: 12
✅ Passed: 10
❌ Failed: 0
⚠️  Warnings: 2
📋 Manual: 2

Report saved to: MFA_TEST_REPORT_20260116_173045.json
```

### Option 2: Manual Testing Only

Skip to **Section: Manual Test Execution** below.

---

## 📋 Manual Test Execution

### Test 1: MFA Setup Page Access (5 minutes)

**Objective:** Verify MFA setup page is accessible and shows available methods.

#### Step 1.1: Test Unauthenticated Access

1. Open browser (Chrome/Firefox/Edge)
2. Clear cookies and cache (Ctrl+Shift+Delete)
3. Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/two-factor/`
4. **Expected:** Redirected to login page
5. **Screenshot:** `test1_1_unauth_redirect.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 1.2: Test Authenticated Access

1. Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/login/`
2. Login with test credentials:
   - Email: _______________
   - Password: _______________
3. After login, navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/two-factor/`
4. **Expected:** Page loads successfully (HTTP 200)
5. **Expected:** Page shows "Two-Factor Authentication" heading
6. **Screenshot:** `test1_2_mfa_setup_page.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 1.3: Check Available MFA Methods

1. On MFA setup page, look for:
   - [ ] "Authenticator App" or "TOTP" option
   - [ ] "Security Key" or "WebAuthn" option
   - [ ] "Enable" or "Activate" buttons
2. **Screenshot:** `test1_3_mfa_methods.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 2: TOTP Setup Flow (10 minutes)

**Objective:** Set up TOTP and verify it works end-to-end.

#### Step 2.1: Navigate to TOTP Activation

1. On MFA setup page, click **"Enable Authenticator App"** or similar button
2. **Expected:** Redirected to TOTP activation page
3. **Expected URL:** `/en-us/accounts/two-factor/totp/activate/`
4. **Screenshot:** `test2_1_totp_activate.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 2.2: Verify QR Code Generation

1. On TOTP activation page, check for:
   - [ ] QR code visible (black/white square pattern)
   - [ ] "Scan with your authenticator app" instructions
   - [ ] Manual entry secret (usually 32-character string)
2. **Screenshot:** `test2_2_qr_code.png` (crop to show QR code clearly)

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 2.3: Scan QR Code with Authenticator App

1. Open Google Authenticator (or Authy/Microsoft Authenticator) on mobile device
2. Tap "+" or "Add account"
3. Select "Scan QR code"
4. Point camera at QR code on screen
5. **Expected:** Account added with name "Zumodra" or user email
6. **Expected:** 6-digit code appears and refreshes every 30 seconds
7. **Screenshot:** `test2_3_auth_app.png` (mobile screenshot)

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 2.4: Verify TOTP Code

1. Get current 6-digit code from authenticator app
2. Enter code in "Verification Code" field on website
3. Click "Verify" or "Submit"
4. **Expected:** Success message: "TOTP activated successfully" or similar
5. **Expected:** Redirected to MFA setup page
6. **Screenshot:** `test2_4_totp_activated.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 2.5: Verify TOTP Status

1. Navigate to `/en-us/accounts/two-factor/`
2. Check TOTP status
3. **Expected:** Shows "Active" or "Enabled" next to Authenticator App
4. **Expected:** Shows "Disable" or "Remove" button
5. **Screenshot:** `test2_5_totp_status.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 3: MFA Challenge on Login (5 minutes)

**Objective:** Verify MFA challenge appears and works correctly.

#### Step 3.1: Logout and Re-login

1. Click user dropdown (usually top-right corner)
2. Click "Logout"
3. Navigate to: `https://zumodra.rhematek-solutions.com/en-us/accounts/login/`
4. Enter email and password
5. Click "Sign In"
6. **Expected:** Redirected to MFA challenge page (NOT dashboard)
7. **Expected:** Page asks for "Authentication Code"
8. **Screenshot:** `test3_1_mfa_challenge.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 3.2: Enter Valid TOTP Code

1. Open authenticator app on mobile
2. Get fresh 6-digit code
3. Enter code on MFA challenge page
4. Click "Verify" or "Submit"
5. **Expected:** Successfully logged in
6. **Expected:** Redirected to dashboard
7. **Screenshot:** `test3_2_mfa_success.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 3.3: Test Invalid Code

1. Logout and login again
2. At MFA challenge, enter wrong code (e.g., "000000")
3. Click "Verify"
4. **Expected:** Error message: "Invalid authentication code" or similar
5. **Expected:** Stays on MFA challenge page
6. **Screenshot:** `test3_3_invalid_code.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 4: Grace Period Enforcement (10 minutes)

**Objective:** Verify new users get 30-day grace period.

#### Step 4.1: Create New Test User (if possible)

**Option A: Create New Account**
1. Logout
2. Go to signup page
3. Create new user:
   - Email: `mfa.test.newuser@example.com`
   - Password: (strong password)
4. Verify email if required
5. Note account creation date/time

**Option B: Use Existing New User**
1. Use account created within last 30 days
2. Verify user does NOT have MFA enabled

#### Step 4.2: Login as New User (No MFA)

1. Login with new user credentials
2. **Expected:** Login succeeds WITHOUT MFA challenge
3. **Expected:** Redirected to dashboard
4. **Screenshot:** `test4_1_new_user_login.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 4.3: Check Dashboard for Reminder

1. On dashboard, look for MFA reminder banner/message
2. **Expected:** Info message like "Consider setting up two-factor authentication"
3. **If 7 days before deadline:** Warning message with days remaining
4. **Screenshot:** `test4_2_grace_reminder.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 4.4: Verify No Forced Redirect

1. Try navigating to various pages:
   - Dashboard: `/en-us/app/dashboard/`
   - ATS Jobs: `/en-us/app/jobs/jobs/`
   - Profile: `/en-us/user/profile/`
2. **Expected:** All pages accessible (NO redirect to MFA setup)
3. **Screenshot:** `test4_3_no_forced_redirect.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 5: MFA Enforcement for Old Users (10 minutes)

**Objective:** Verify users >30 days old are forced to set up MFA.

**Note:** This test requires a user account created more than 30 days ago.

#### Step 5.1: Identify Old User Account

**Option A: Use Existing Old Account**
1. Login as user created >30 days ago
2. Verify user does NOT have MFA enabled

**Option B: Check Database (Admin Access Required)**
```sql
SELECT email, date_joined
FROM auth_user
WHERE date_joined < NOW() - INTERVAL '30 days'
  AND id NOT IN (
      SELECT user_id FROM allauth_mfa_authenticator WHERE is_active = TRUE
  )
LIMIT 5;
```

#### Step 5.2: Test Forced Redirect

1. Login with old user credentials
2. **Expected:** Immediately redirected to `/en-us/accounts/two-factor/`
3. **Expected:** Warning message: "Two-factor authentication is required"
4. **Screenshot:** `test5_1_forced_redirect.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 5.3: Test Protected Pages Blocked

1. Try to navigate directly to `/en-us/app/dashboard/`
2. **Expected:** Redirected back to `/en-us/accounts/two-factor/`
3. Try other protected pages:
   - `/en-us/app/jobs/jobs/`
   - `/en-us/app/hr/employees/`
4. **Expected:** All redirect to MFA setup
5. **Screenshot:** `test5_2_blocked_access.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 5.4: Verify Exempt Paths Work

1. While blocked from dashboard, try:
   - Logout: `/en-us/accounts/logout/` - Should work
   - Static files: `/static/css/style.css` - Should load
   - API health: `/api/health/` - Should return JSON
2. **Expected:** All exempt paths work without redirect
3. **Screenshot:** `test5_3_exempt_paths.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 6: Navigation Integration (5 minutes)

**Objective:** Verify MFA link is in navigation menus.

#### Step 6.1: Check User Dropdown Menu

1. Login as authenticated user
2. Click user dropdown (usually top-right corner with avatar/name)
3. Look for "Two-Factor Auth" or "MFA" link
4. **Expected:** Link is visible and clickable
5. **Screenshot:** `test6_1_user_dropdown.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 6.2: Check for Setup Badge

1. If MFA not enabled, check for "Setup" badge next to MFA link
2. **Expected:** Badge appears in red or orange color
3. **Screenshot:** `test6_2_setup_badge.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 6.3: Test MFA Link Navigation

1. Click "Two-Factor Auth" link in dropdown
2. **Expected:** Navigates to `/en-us/accounts/two-factor/`
3. **Expected:** MFA setup page loads
4. **Screenshot:** `test6_3_mfa_link_nav.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 7: Backup Codes (10 minutes)

**Objective:** Verify backup codes generation and usage.

#### Step 7.1: Generate Backup Codes

1. Navigate to: `/en-us/accounts/two-factor/recovery-codes/`
2. Click "Generate Backup Codes" or similar button
3. **Expected:** List of 8-10 backup codes displayed
4. **Expected:** Each code is 8-10 characters (alphanumeric)
5. **Screenshot:** `test7_1_backup_codes.png`
6. **Save one code for testing:** _______________

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 7.2: Test Login with Backup Code

1. Logout
2. Login with username/password
3. At MFA challenge, look for "Use backup code" link
4. Click link
5. Enter saved backup code
6. **Expected:** Login succeeds
7. **Screenshot:** `test7_2_backup_login.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 7.3: Verify Code Invalidation

1. Logout and login again
2. Try to reuse the SAME backup code
3. **Expected:** Error message: "Invalid code" or "Code already used"
4. **Screenshot:** `test7_3_code_invalidated.png`

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

### Test 8: Middleware Functionality (5 minutes)

**Objective:** Verify no redirect loops or blocking issues.

#### Step 8.1: Test for Redirect Loops

1. Open browser DevTools (F12)
2. Go to Network tab
3. Navigate to `/en-us/accounts/two-factor/`
4. Check Network tab for repeated redirects
5. **Expected:** Single request, no loops
6. **Screenshot:** `test8_1_no_loops.png` (Network tab)

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

#### Step 8.2: Test Session Reminder (Once Per Session)

1. Login as new user (grace period active)
2. Go to dashboard - Note if reminder appears
3. Navigate away and back to dashboard
4. **Expected:** Reminder shown only ONCE per session
5. **Expected:** No reminder on subsequent page loads
6. Logout and login again
7. **Expected:** Reminder appears again (new session)

**Result:** ✅ PASS / ❌ FAIL
**Notes:** _________________

---

## 📊 Test Summary

### Results Overview

| Test # | Test Name | Result | Time | Notes |
|--------|-----------|--------|------|-------|
| 1 | MFA Setup Page Access | ✅/❌ | ___ min | |
| 2 | TOTP Setup Flow | ✅/❌ | ___ min | |
| 3 | MFA Challenge on Login | ✅/❌ | ___ min | |
| 4 | Grace Period Enforcement | ✅/❌ | ___ min | |
| 5 | Old User MFA Enforcement | ✅/❌ | ___ min | |
| 6 | Navigation Integration | ✅/❌ | ___ min | |
| 7 | Backup Codes | ✅/❌ | ___ min | |
| 8 | Middleware Functionality | ✅/❌ | ___ min | |

**Total Tests:** 8
**Passed:** ___
**Failed:** ___
**Total Time:** ___ minutes

---

## 🐛 Issues Found

### Critical Issues (Must Fix)

1. **Issue:** _______________
   **Steps to Reproduce:** _______________
   **Expected:** _______________
   **Actual:** _______________
   **Screenshot:** _______________

2. **Issue:** _______________
   **Steps to Reproduce:** _______________
   **Expected:** _______________
   **Actual:** _______________
   **Screenshot:** _______________

### Non-Critical Issues (Should Fix)

1. **Issue:** _______________
   **Details:** _______________

2. **Issue:** _______________
   **Details:** _______________

---

## ✅ Final Checklist

Before submitting test report, verify:

- [ ] All 8 tests completed
- [ ] Screenshots captured and organized
- [ ] Issues documented with reproduction steps
- [ ] Test results summary filled out
- [ ] No critical blockers found (or documented)
- [ ] MFA middleware confirmed working
- [ ] No redirect loops detected
- [ ] Grace period works correctly
- [ ] Old user enforcement works correctly

---

## 📝 Test Report Submission

**Submit to:** [Project Manager/Team Lead]

**Include:**
1. This completed checklist
2. All screenshots (in `MFA_Test_Screenshots_20260116` folder)
3. Automated test report: `MFA_TEST_REPORT_*.json`
4. Any screen recordings (if applicable)

**Format:** ZIP file named: `MFA_Test_Results_YYYYMMDD.zip`

---

## 🔗 Additional Resources

- **Implementation Guide:** `MFA_IMPLEMENTATION_GUIDE.md`
- **Full Testing Checklist:** `MFA_TESTING_CHECKLIST.md`
- **Quick Reference:** `MFA_TEST_SUMMARY.md`
- **Automated Test Script:** `test_mfa_enforcement.py`

---

## 📞 Support Contacts

**Technical Issues:**
- Rhematek Solutions
- Email: support@rhematek.com

**Access Issues:**
- Server: zumodra.rhematek-solutions.com
- Contact: [Admin Name]

---

**Good luck with testing! 🚀**

**Remember:** Take your time, be thorough, and document everything with screenshots.

---

**End of Test Execution Guide**
