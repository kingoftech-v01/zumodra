# 🚀 Zumodra Launch Checklist

**Follow these steps in order to get your website running!**

---

## ✅ Pre-Launch Checklist

### 1. Install Dependencies
```bash
# Activate virtual environment
.venv\Scripts\activate

# Install all packages
pip install -r requirements.txt
```
**Estimated time:** 5-10 minutes

---

### 2. Verify Environment File
```bash
# Check that .env file exists and has correct values
# Compare with .env.example
```

**Required in .env:**
- ✅ `SECRET_KEY`
- ✅ `DEBUG=True`
- ✅ `DB_PASSWORD`
- ✅ `EMAIL_HOST_PASSWORD`
- ✅ `STRIPE_SECRET_KEY` (can be empty for now)

---

### 3. Start PostgreSQL
Make sure PostgreSQL is running on port **5433**

**Windows:**
- Check Services → PostgreSQL
- Or use pgAdmin

**Linux/Mac:**
```bash
sudo service postgresql start
```

---

### 4. Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

**Expected output:**
```
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  ...
  Applying wagtailcore.0001_initial... OK
  ...
```

**Estimated time:** 2-3 minutes

---

### 5. Create Superuser
```bash
python manage.py createsuperuser
```

**You'll be asked for:**
- Email address
- Password
- Password confirmation

**Remember these credentials!** You'll need them to access:
- Django Admin: `/admin-panel/`
- Wagtail CMS: `/cms/`

---

### 6. Collect Static Files
```bash
python manage.py collectstatic --noinput
```

**Expected output:**
```
X static files copied to '/path/to/zumodra/static'
```

---

### 7. Start Development Server
```bash
python manage.py runserver
```

**Expected output:**
```
Django version X.X.X, using settings 'zumodra.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

---

### 8. Access Wagtail CMS
**Open browser:** http://localhost:8000/cms/

**Login with superuser credentials**

---

### 9. Create Root Page Structure

**Option A: Via Wagtail Admin (Recommended)**
1. Go to http://localhost:8000/cms/
2. Click "Pages"
3. Click "Welcome to your new Wagtail site!"
4. Add child page → Choose "Blog Index Page"
5. Fill in:
   - Title: "Blog"
   - Slug: "blog"
   - Intro: "Welcome to our blog"
6. Click "Publish"

**Option B: Via Django Shell**
```bash
python manage.py shell
```

```python
from wagtail.models import Page
from blog.models import BlogIndexPage

root = Page.objects.get(id=1)
blog = BlogIndexPage(
    title="Blog",
    slug="blog",
    intro="Welcome to our blog"
)
root.add_child(instance=blog)
blog.save_revision().publish()
print("Blog created!")
exit()
```

---

### 10. Create Your First Blog Post

**Via Wagtail CMS:**
1. Go to http://localhost:8000/cms/
2. Navigate to Pages → Blog
3. Click "Add child page" → "Blog Post Page"
4. Fill in:
   - Title: "Welcome to Zumodra"
   - Excerpt: "Our first blog post!"
   - Body: Add content using StreamField blocks
   - Featured image: Upload an image
   - Status: "Published"
5. Click "Publish"

---

### 11. Test Public Website

**Visit:** http://localhost:8000

**Check:**
- ✅ Homepage loads
- ✅ Navigation works (Home, About, Privacy, Terms)
- ✅ "Sign In" and "Get Started" buttons visible
- ✅ No error messages

---

### 12. Test Authentication

**Sign Up:**
1. Click "Get Started"
2. Fill in registration form
3. Check email for verification (or check console if using DEBUG)
4. Verify email
5. Set up 2FA

**Sign In:**
1. Click "Sign In"
2. Enter credentials
3. Enter 2FA code
4. Should redirect to homepage
5. "Dashboard" button should appear

---

### 13. Test Admin Access

**Django Admin:**
- URL: http://localhost:8000/admin-panel/
- Login with superuser
- Should see Django admin interface

**Wagtail CMS:**
- URL: http://localhost:8000/cms/
- Login with superuser
- Should see Wagtail dashboard

---

### 14. Test Blog

**Visit blog page:**
- If created at root: http://localhost:8000/blog/
- Or wherever you created BlogIndexPage

**Check:**
- ✅ Blog post appears
- ✅ Can click to read full post
- ✅ Featured image displays
- ✅ Content renders correctly

---

## 🐳 Docker Launch (Alternative)

If you prefer Docker:

```bash
# Build and start
docker-compose up --build

# In another terminal - run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Collect static
docker-compose exec web python manage.py collectstatic --noinput
```

**Access:**
- Nginx: http://localhost:80
- Django: http://localhost:8000

---

## ⚠️ Common Issues

### Issue: Can't Install Dependencies
**Error:** `Could not find a version that satisfies the requirement...`

**Solution:**
```bash
# Upgrade pip
python -m pip install --upgrade pip

# Try again
pip install -r requirements.txt
```

---

### Issue: Database Connection Failed
**Error:** `could not connect to server`

**Solution:**
1. Check PostgreSQL is running
2. Verify `.env` credentials:
   ```env
   DB_HOST=localhost
   DB_PORT=5433
   DB_USER=postgres
   DB_PASSWORD=your-password
   ```
3. Test connection:
   ```bash
   psql -h localhost -p 5433 -U postgres
   ```

---

### Issue: Migrations Fail
**Error:** `django.db.utils.OperationalError`

**Solution:**
1. Drop and recreate database:
   ```sql
   DROP DATABASE zumodra;
   CREATE DATABASE zumodra;
   ```
2. Run migrations again

---

### Issue: Static Files 404
**Error:** CSS/JS not loading

**Solution:**
```bash
python manage.py collectstatic --noinput
```

**For development, also check:**
```python
# settings.py
DEBUG = True  # Must be True for dev server to serve static
```

---

### Issue: Can't Access Wagtail Pages
**Error:** 404 on blog URLs

**Solution:** You must create pages in Wagtail CMS first!
1. Go to `/cms/`
2. Create BlogIndexPage
3. Create BlogPostPage
4. Publish them

---

### Issue: 2FA Required Error
**Error:** Can't access site without 2FA

**Solution:**
```python
# In settings.py, temporarily disable:
ALLAUTH_2FA_FORCE_2FA = False
TWO_FACTOR_MANDATORY = False
```

**Or set up 2FA properly via account settings**

---

## ✅ Final Verification

Before going live, verify:

**Functionality:**
- [  ] Homepage loads
- [  ] All navigation links work
- [  ] Can create and view blog posts
- [  ] Authentication works (sign up/sign in)
- [  ] Dashboard accessible when logged in
- [  ] Admin panels accessible
- [  ] Static files load (CSS, JS, images)
- [  ] Media uploads work

**Security:**
- [  ] SECRET_KEY is from .env (not hardcoded)
- [  ] DEBUG=True for development
- [  ] Database password is secure
- [  ] .env file not in git (.gitignore)
- [  ] ALLOWED_HOSTS configured

**Content:**
- [  ] Wagtail homepage created
- [  ] At least one blog post published
- [  ] About page has content
- [  ] Privacy policy filled in
- [  ] Terms of service filled in

---

## 🎉 You're Live!

Once all checks pass, your website is ready!

**Public URL:** http://localhost:8000

**Admin URLs:**
- Django Admin: http://localhost:8000/admin-panel/
- Wagtail CMS: http://localhost:8000/cms/

**Next Steps:**
1. Create more blog content
2. Customize templates
3. Add your branding/logo
4. Configure email settings
5. Set up Stripe for payments
6. Deploy to production server

---

## 📚 Need Help?

Check these docs:
- **[STARTUP_INSTRUCTIONS.md](STARTUP_INSTRUCTIONS.md)** - Detailed setup guide
- **[WORK_COMPLETED_SUMMARY.md](WORK_COMPLETED_SUMMARY.md)** - What was done
- **[BUGS_AND_FIXES.md](BUGS_AND_FIXES.md)** - Troubleshooting
- **[PROJECT_PLAN.md](PROJECT_PLAN.md)** - Full project info

---

**Good luck with your launch! 🚀**
