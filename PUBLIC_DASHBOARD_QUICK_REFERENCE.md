# Public User Dashboard - Quick Reference Card

**Target:** https://zumodra.rhematek-solutions.com/app/dashboard/
**Template:** `templates/dashboard/public_user_dashboard.html`
**For:** Users WITHOUT tenant membership

---

## 🎯 8 Features to Test

| # | Feature | What to Check | Pass? |
|---|---------|---------------|-------|
| 1 | **Welcome Banner** | Blue→indigo gradient, user's name, "Complete your profile" | ☐ |
| 2 | **MFA Warning** | Yellow banner if NO MFA, hidden if MFA enabled | ☐ |
| 3 | **Profile Widget** | 0-100% based on bio, phone, location, linkedin_url | ☐ |
| 4 | **Quick Actions** | 3 cards: Jobs (blue), Services (green), 2FA (purple) | ☐ |
| 5 | **Recommended Jobs** | Max 5 jobs OR empty state with briefcase icon | ☐ |
| 6 | **Join Org CTA** | Purple→pink gradient, 2 buttons | ☐ |
| 7 | **Dark Mode** | All sections adapt, good contrast | ☐ |
| 8 | **Responsive** | 3 cols desktop → 1 col mobile | ☐ |

---

## ⚡ Quick Test Commands

### Selenium (Screenshots) - FASTEST
```bash
pip install selenium webdriver-manager pillow
# Edit test_public_dashboard_selenium.py with credentials
python test_public_dashboard_selenium.py
# Screenshots in test_screenshots/
```

### Automated Tests (Docker)
```bash
docker compose up -d
docker compose exec web pytest test_public_user_dashboard.py -v
```

### Manual HTTP
```bash
pip install requests
python test_public_dashboard_manual.py
# Enter credentials when prompted
```

---

## 👥 Test Users Needed

| User | Tenant? | MFA? | Profile? |
|------|---------|------|----------|
| User A | ❌ No | ❌ No | Empty (0%) |
| User B | ❌ No | ✅ Yes | Full (100%) |
| User C | ❌ No | ❌ No | Partial (50%) |

**CRITICAL:** Users must have NO tenant membership!

---

## 📸 Screenshots to Capture

### Desktop (1920px)
- [ ] Full dashboard
- [ ] Welcome banner
- [ ] MFA warning (if no MFA)
- [ ] Profile widget (0%, 50%, 100%)
- [ ] Quick actions + hover
- [ ] Jobs section or empty state
- [ ] Join org CTA
- [ ] Dark mode view

### Mobile (375px)
- [ ] Full dashboard
- [ ] Stacked layout

---

## ✅ Success Checklist

- [ ] Template loads (HTTP 200)
- [ ] Welcome banner shows with gradient
- [ ] MFA banner shows/hides correctly
- [ ] Profile % calculates correctly
- [ ] All 3 quick action cards show
- [ ] Jobs display or empty state
- [ ] Join org CTA displays
- [ ] Dark mode works
- [ ] Mobile layout stacks
- [ ] All links work
- [ ] No console errors

---

## 🐛 Common Issues

| Issue | Fix |
|-------|-----|
| Wrong template loads | User has tenant membership - use public user |
| MFA banner always shows | Check user.mfa_authenticators |
| Profile always 0% | Ensure UserProfile has bio, phone, location, linkedin_url |
| No jobs show | Create PublicJobCatalog entries |
| Links give 404 | Check URL patterns exist |

---

## 📁 Files Reference

| File | Purpose |
|------|---------|
| `PUBLIC_DASHBOARD_TESTING_INDEX.md` | Complete index (start here) |
| `PUBLIC_DASHBOARD_TEST_SUMMARY.md` | Quick summary |
| `PUBLIC_DASHBOARD_TEST_GUIDE.md` | Detailed guide |
| `PUBLIC_USER_DASHBOARD_TEST_CHECKLIST.md` | 66-point checklist |
| `test_public_dashboard_selenium.py` | Browser automation |
| `test_public_user_dashboard.py` | Pytest tests (66+) |
| `test_public_dashboard_manual.py` | HTTP tests |

---

## 🎓 Helper Methods

```python
# Profile completion (0-100%)
_calculate_profile_completion(user)
# Checks: bio, phone, location, linkedin_url

# Recommended jobs
_get_recommended_jobs(user)
# Returns: PublicJobCatalog.objects.filter(is_active=True)

# MFA check
_user_has_mfa(user)
# Returns: user.mfa_authenticators.filter(is_active=True).exists()
```

---

## 📊 Quick Stats

- **Files:** 9 total (6 docs + 3 test scripts)
- **Tests:** 66+ automated test cases
- **Coverage:** 100% of features
- **Time:** ~55 min for complete testing

---

**🚀 Ready to test? Choose Selenium for quickest visual verification!**

```bash
python test_public_dashboard_selenium.py
```
