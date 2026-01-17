# Server Testing Plan - Public User Fixes

## Test Environment
- Server: zumodra.rhematek-solutions.com
- Date: 2026-01-17
- Commits Deployed:
  - 61cad1c: Signup links fix
  - 93b1d55: Notifications schema fix
  - ad122ab: Finance schema fix

## Test Scenarios

### 1. Public User Signup Flow
**Expected**: Users can choose account type and register successfully

**Steps**:
1. Visit https://zumodra.rhematek-solutions.com/
2. Click "Sign Up" button (desktop navigation)
3. Verify account type selection page loads (3 cards: Public/Company/Freelancer)
4. Select "Public User (Free)"
5. Click "Continue to Sign Up"
6. Fill signup form (email, password, first name, last name)
7. Submit form
8. Verify account created successfully

**Pass Criteria**:
- ✓ Account type selection page displays correctly
- ✓ All 3 account types visible
- ✓ Signup form loads after selecting type
- ✓ Registration completes without errors
- ✓ User is logged in automatically

---

### 2. Dashboard Access for Public Users
**Expected**: Dashboard loads without "An error occurred" message

**Steps**:
1. Login as public user (created in Test 1)
2. Navigate to /app/dashboard/
3. Verify page loads completely
4. Check for any error messages
5. Verify notification dropdown is accessible (shows 0 notifications)

**Pass Criteria**:
- ✓ Dashboard loads without errors
- ✓ No "An error occurred" message
- ✓ Public user dashboard template displays
- ✓ Profile completion widget visible
- ✓ Notification icon shows 0 notifications
- ✓ No console errors

---

### 3. Finance Pages for Public Users
**Expected**: Finance pages load gracefully with empty state

**Steps**:
1. While logged in as public user
2. Navigate to /app/finance/
3. Verify page loads (may show upgrade message or empty state)
4. Navigate to /app/finance/payments/
5. Verify page loads without crash
6. Navigate to /app/finance/invoices/
7. Verify page loads without crash
8. Navigate to /app/finance/subscription/
9. Verify page loads without crash

**Pass Criteria**:
- ✓ All finance pages load without ProgrammingError
- ✓ Pages show empty state or upgrade message
- ✓ No database relation errors in logs
- ✓ Navigation works smoothly

---

### 4. Notifications for Public Users
**Expected**: Notification system handles public users gracefully

**Steps**:
1. While logged in as public user
2. Click notification icon in header
3. Verify dropdown shows "0 notifications"
4. Navigate to /app/notifications/ (if link exists)
5. Verify page loads with empty list

**Pass Criteria**:
- ✓ Notification dropdown opens without errors
- ✓ Shows 0 notifications (not crash)
- ✓ Full notifications page loads (if accessible)
- ✓ No schema errors in console

---

### 5. API Endpoints Testing
**Expected**: Public API endpoints return data, authenticated endpoints reject public users

**Public Endpoints (No Auth Required)**:
```bash
# Test careers API
curl https://zumodra.rhematek-solutions.com/api/v1/careers/jobs/

# Test careers page config
curl https://zumodra.rhematek-solutions.com/api/v1/careers/page/

# Test health check
curl https://zumodra.rhematek-solutions.com/health/
```

**Pass Criteria**:
- ✓ /api/v1/careers/jobs/ returns job list (200 OK)
- ✓ /api/v1/careers/page/ returns page config (200 OK)
- ✓ /health/ returns healthy status (200 OK)
- ✓ All responses are valid JSON
- ✓ No 500 errors

---

### 6. Authenticated API Endpoints
**Expected**: Require authentication, reject unauthenticated requests

```bash
# Test ATS API (should require auth)
curl https://zumodra.rhematek-solutions.com/api/v1/ats/jobs/

# Test HR API (should require auth)
curl https://zumodra.rhematek-solutions.com/api/v1/hr/employees/
```

**Pass Criteria**:
- ✓ Returns 401 Unauthorized or 403 Forbidden
- ✓ Does not return 500 Internal Server Error
- ✓ Error message is appropriate

---

### 7. Mobile Navigation Testing
**Expected**: All signup buttons work on mobile

**Steps**:
1. Open site on mobile device (or mobile view)
2. Open mobile menu
3. Click "Sign Up" link
4. Verify account type selection page loads

**Pass Criteria**:
- ✓ Mobile menu opens correctly
- ✓ Signup link navigates to type selection
- ✓ No broken links

---

### 8. Landing Page Signup Links
**Expected**: All landing pages use correct signup URL

**Pages to Test**:
- / (homepage)
- /careers/ (public landing)
- /contact/
- /become-seller/
- /become-buyer/

**Steps**:
1. Visit each page
2. Find "Sign Up" or "Get Started" buttons
3. Click each button
4. Verify redirects to account type selection

**Pass Criteria**:
- ✓ All signup buttons work
- ✓ All redirect to /user/signup/choose/
- ✓ No 404 errors

---

### 9. Error Logging Verification
**Expected**: No ProgrammingError or relation errors in logs

**Steps**:
1. SSH into server
2. Check Django logs:
   ```bash
   tail -f /var/log/zumodra/web.log
   ```
3. Perform all above tests while monitoring logs
4. Search for errors:
   ```bash
   grep -i "programmingError" /var/log/zumodra/web.log
   grep -i "relation.*does not exist" /var/log/zumodra/web.log
   ```

**Pass Criteria**:
- ✓ No ProgrammingError exceptions
- ✓ No "relation does not exist" errors
- ✓ Only expected warnings/info logs

---

### 10. Session Persistence
**Expected**: User stays logged in, sessions work correctly

**Steps**:
1. Login as public user
2. Navigate to different pages
3. Wait 5 minutes
4. Refresh page
5. Verify still logged in

**Pass Criteria**:
- ✓ Session persists across page loads
- ✓ User not randomly logged out
- ✓ Session cookie valid for 8 hours

---

### 11. Cross-Browser Testing
**Expected**: Works on all major browsers

**Browsers to Test**:
- Chrome/Edge
- Firefox
- Safari (if available)

**Pass Criteria**:
- ✓ Signup flow works on all browsers
- ✓ Dashboard loads on all browsers
- ✓ No browser-specific JavaScript errors

---

### 12. Final Verification
**Expected**: Complete user journey works end-to-end

**Complete Journey**:
1. Visit homepage
2. Click signup
3. Choose "Public User"
4. Complete registration
5. Verify email (if enabled)
6. Access dashboard
7. View notifications (0)
8. Try to access finance pages
9. Browse public jobs at /careers/
10. Logout
11. Login again
12. All works correctly

**Pass Criteria**:
- ✓ No errors at any step
- ✓ User can complete entire journey
- ✓ All pages load correctly
- ✓ System is stable and usable

---

## Success Metrics

**MUST PASS (Critical)**:
- [ ] Public users can register without errors
- [ ] Dashboard loads without "An error occurred"
- [ ] Finance pages don't crash
- [ ] Notifications work without schema errors
- [ ] No ProgrammingError in logs

**SHOULD PASS (Important)**:
- [ ] All signup links use correct URL
- [ ] API endpoints return expected status codes
- [ ] Mobile navigation works
- [ ] Sessions persist correctly

**NICE TO HAVE (Enhancement)**:
- [ ] Cross-browser compatibility
- [ ] Fast page load times
- [ ] Good UX/UI experience

---

## Test Execution Log

### Date: [To be filled during testing]
### Tester: [Name]
### Environment: zumodra.rhematek-solutions.com

| Test # | Test Name | Status | Notes |
|--------|-----------|--------|-------|
| 1 | Signup Flow | [ ] PASS / [ ] FAIL | |
| 2 | Dashboard Access | [ ] PASS / [ ] FAIL | |
| 3 | Finance Pages | [ ] PASS / [ ] FAIL | |
| 4 | Notifications | [ ] PASS / [ ] FAIL | |
| 5 | Public API | [ ] PASS / [ ] FAIL | |
| 6 | Auth API | [ ] PASS / [ ] FAIL | |
| 7 | Mobile Navigation | [ ] PASS / [ ] FAIL | |
| 8 | Landing Pages | [ ] PASS / [ ] FAIL | |
| 9 | Error Logs | [ ] PASS / [ ] FAIL | |
| 10 | Session Persistence | [ ] PASS / [ ] FAIL | |
| 11 | Cross-Browser | [ ] PASS / [ ] FAIL | |
| 12 | End-to-End | [ ] PASS / [ ] FAIL | |

---

## Issues Found

### Issue Template:
**Issue #**: [Number]
**Test**: [Which test found it]
**Severity**: Critical / High / Medium / Low
**Description**: [What went wrong]
**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]

**Expected**: [What should happen]
**Actual**: [What happened]
**Fix Required**: [What needs to be done]

---

## Deployment Verification

Before testing, verify deployment is complete:

```bash
# SSH into server
ssh zumodra

# Navigate to project
cd zumodra.rhematek-solutions.com

# Check current commit
git log --oneline -1

# Expected commit: ad122ab or later
```

If not on latest commit:
```bash
git pull origin main
sudo systemctl restart zumodra-web
sudo systemctl restart zumodra-channels
```

---

## Conclusion

**Overall Status**: [ ] ALL TESTS PASSED / [ ] SOME FAILURES / [ ] CRITICAL FAILURES

**Summary**: [Brief summary of test results]

**Next Steps**: [What needs to be done based on results]
