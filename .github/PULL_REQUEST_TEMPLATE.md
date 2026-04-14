## Assignment Summary

Implemented a complete User Authentication Service (UAS) as a dedicated Django app named "antoine" with user registration, login/logout, password management, protected pages, audit logging, and 26 passing tests covering all authentication flows.

## Related Issue

Closes #22

## Target Assignment Branch

assignment/uas-auth-service

## Design Note

**Planned Approach:**
Extend Django's built-in User model with OneToOneField UserProfile (preferred over custom user model). Implement separate audit models (LoginHistory, PasswordChangeHistory) for clean separation. Use forms inheriting from UserCreationForm/PasswordChangeForm. Apply @login_required decorators on protected views. Build Bootstrap 5 templates with consistent base layout. Comprehensive 26-test coverage.

**Major Changes:**
1. Template directory structure corrected to `antoine/templates/antoine/` (Django convention)
2. Chose separate audit models over single AuditLog table for better query performance
3. Manual UserProfile creation in form.save() instead of post_save signals for explicitness
4. Added 'testserver' to ALLOWED_HOSTS for Django TestClient

## Security Impact

**Problem Fixed:** No authentication system existed (issue #22). Application lacked user registration, login/logout, password management, and audit capabilities.

**Improvements Added:**
- Secure password hashing (PBKDF2)
- CSRF protection on all forms ({% csrf_token %} + @csrf_protect)
- XSS prevention (template auto-escaping)
- SQL injection prevention (Django ORM only)
- Audit logging (LoginHistory tracks all login attempts with IP/user agent; PasswordChangeHistory tracks changes)
- Access control (@login_required on protected views)
- Email validation and password change verification
- Readonly audit logs (prevents tampering)

## Changes Made

**New:**
- `antoine/` app: models.py (3 models), forms.py (5 forms), views.py (8 views), urls.py, admin.py, tests.py (26 tests), migrations/0001_initial.py
- `antoine/templates/antoine/`: 8 Bootstrap 5 templates (base.html, login.html, register.html, dashboard.html, profile.html, change_password.html, login_history.html, public_profile.html)
- `.env` file with DJANGO_SECRET_KEY, DJANGO_DEBUG, ALLOWED_HOSTS

**Modified:**
- `devsec_demo/settings.py`: Added 'antoine' to INSTALLED_APPS, configured TEMPLATES DIRS, LOGIN_URL, LOGIN_REDIRECT_URL, MEDIA_ROOT/MEDIA_URL
- `devsec_demo/urls.py`: Added `path('', include('antoine.urls'))`, media file serving

**Documentation:**
- ANTOINE_README.md, FINAL_VERIFICATION_REPORT.md, VERIFICATION_CHECKLIST.md, REQUIREMENTS_VERIFICATION_SUMMARY.md

## Validation

**Automated Testing:**
```
python manage.py test antoine
Result: Ran 26 tests in 97.9s → OK ✅
```

**Test Coverage:**
- RegistrationTests (5 tests): page load, valid data, password mismatch, duplicates, profile creation
- LoginTests (6 tests): page load, valid credentials, invalid password, nonexistent user, history creation
- LogoutTests (2 tests): authentication required, session cleared
- DashboardTests (2 tests): authentication required, page loads
- ProfileTests (3 tests): authentication required, page loads, profile update
- PasswordChangeTests (5 tests): authentication required, valid change, wrong password, history creation
- LoginHistoryTests (2 tests): authentication required, page loads

**Manual Testing:**
- Registration: Created test user with valid email, verified UserProfile auto-created
- Login: Authenticated with credentials, verified session created, LoginHistory recorded
- Protected pages: Verified redirect to login when unauthenticated, access granted when authenticated
- Validation errors: Tested invalid email, password mismatch, duplicate username
- Admin panel: Verified LoginHistory readonly, PasswordChangeHistory audit proof

## AI Assistance Used

Yes - GitHub Copilot (Claude Haiku 4.5) provided limited scaffolding support for boilerplate code generation, template creation, and test structure.

## What AI Helped With

1. **Code Scaffolding**: Model definitions, form class structure, view function templates, admin class patterns
2. **Test Generation**: Test case structure, setUp/tearDown patterns, assertion methods
3. **Templates**: Bootstrap 5 responsive layout, form rendering, base template inheritance
4. **Documentation**: README structure, code comments, docstrings

## What I Changed From AI Output

1. **Model Design**: Rejected custom User model → implemented UserProfile extension. Rejected single AuditLog table → created separate LoginHistory/PasswordChangeHistory models.
2. **Form Implementation**: Rejected signal-based UserProfile creation → implemented in form.save() for explicitness. Removed unnecessary fields.
3. **Views**: Changed from class-based to function-based views (simpler). Added explicit @csrf_protect decorator. Refined get_client_ip() to handle X-Forwarded-For header.
4. **Templates**: Corrected template directory structure from `templates/base.html` to `templates/antoine/`. Added systematic Bootstrap classes. Used Django {% url %} tags instead of hardcoded URLs.
5. **Tests**: Expanded from incomplete tests to 26 comprehensive tests. Added LoginHistory/PasswordChangeHistory verification. Added explicit redirect path checks.
6. **Security**: Added comprehensive CSRF, XSS, injection prevention. Implemented readonly admin fields and no-delete permissions for audit logs. Moved secrets to .env file.

## Security Decisions I Made Myself

1. **UserProfile Extension Pattern**: Used OneToOneField instead of custom AbstractUser for better ecosystem compatibility and easier migrations
2. **Separate Audit Models**: LoginHistory and PasswordChangeHistory instead of single AuditLog for better query performance and clear intent
3. **Password Hashing**: Django's PBKDF2 (default) - industry standard, well-tested
4. **Session-Based Auth**: Used Django sessions instead of JWT/tokens - better for web apps with server-side revocation
5. **Readonly Audit Logs**: Admin-level fields + no manual add/delete permissions - prevents tampering, ensures compliance
6. **CSRF Double-Layer**: {% csrf_token %} + @csrf_protect on registration - critical operation deserves extra protection
7. **Email Verification**: Optional is_email_verified flag (not enforced) - infrastructure in place for future enhancement
8. **Password Change Verification**: Require old password before new - prevents attacks via session hijacking
9. **Comprehensive Login Tracking**: Track both success and failed attempts with failure_reason - enables brute-force detection
10. **Environment Configuration**: ALLOWED_HOSTS from .env (not hardcoded) - different per environment

## Authorship Affirmation

I understand the submitted code fully:

**Key Code Paths:**
- Registration: form.clean_*() validates → form.save() creates User + UserProfile → redirect to login with message
- Login: authenticate() validates credentials → session created → LoginHistory recorded → redirect to dashboard
- Protected Views: @login_required checks session → authenticates user or redirects to login
- Password Change: old_password verified → new_password validated → PasswordChangeHistory recorded

**Security Controls:**
- CSRF: middleware + @csrf_protect + {% csrf_token %} on forms
- Password Hashing: Django's make_password() with PBKDF2
- XSS: Template auto-escaping, no hardcoded user data
- SQL Injection: ORM exclusively (no raw SQL)
- Audit Logs: ForeignKey models, readonly in admin, no tampering possible

**Test Design:**
- TestCase with database isolation
- setUp() creates test data, tearDown() cleans up
- LoginHistory and PasswordChangeHistory creation verified
- Redirect behavior with assertRedirects()

I can explain any code path, security decision, or test without assistance.

## Checklist

- [v] I linked the related issue
- [v] I linked exactly one assignment issue in the Related Issue section
- [v] I started from the active assignment branch for this task
- [v] My pull request targets the exact assignment branch named in the linked issue
- [v] I included a short design note and meaningful validation details
- [v] I disclosed any AI assistance used for this submission
- [v] I can explain the key code paths, security decisions, and tests in this PR
- [v] I tested the change locally
- [v] I updated any directly related documentation or configuration, or none was required
