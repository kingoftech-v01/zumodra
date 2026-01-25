"""
Blog Signals Module - Django Signals for Automation
====================================================

This module defines Django signals to automate the creation and
synchronization of user profiles (UserProfile) with Django's User model.

Defined Signals:
----------------
- create_user_profile: Automatically creates UserProfile when User is created
- save_user_profile: Syncs UserProfile when User is saved

Workflow:
---------
1. When a new User is created (via admin, registration, etc.):
   → post_save signal is emitted with created=True
   → create_user_profile() intercepts and creates an empty UserProfile
   → User now has an accessible profile via user.profile

2. When an existing User is saved:
   → post_save signal is emitted with created=False
   → save_user_profile() intercepts and saves the profile
   → Ensures synchronization between User and UserProfile

Loading:
--------
These signals are automatically loaded via blog/apps.py:

    class BlogConfig(AppConfig):
        def ready(self):
            import blog.signals  # ← Loads signals at startup

Important:
----------
- NEVER import this module anywhere except in apps.py
- Signals are loaded ONCE at Django startup
- Any modification requires server restart

Usage Example:
--------------
    # Creating a User automatically triggers profile creation
    user = User.objects.create_user(username='john', password='pass')
    print(user.profile)  # <UserProfile: Profile of john>
    print(user.profile.avatar)  # None (default)

    # Updating the profile
    user.profile.bio = "Hello World"
    user.save()  # ← Triggers save_user_profile()
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler to automatically create UserProfile when a User is created.

    This signal is triggered immediately after a new User object is created
    (via User.objects.create(), User.objects.create_user(), admin, etc.). It creates
    an empty UserProfile associated with the User, ensuring all Users have a profile.

    Args:
        sender (Model class): The model class that emitted the signal (User)
        instance (User): The User instance that was just created/saved
        created (bool): True if new creation, False if update
        **kwargs: Additional signal arguments (using, update_fields, raw, etc.)

    Behavior:
        - If created=True: Creates a new UserProfile linked to the User instance
        - If created=False: Does nothing (not a new creation)

    Side Effects:
        - Creates a UserProfile record in database
        - Accessible via instance.profile (OneToOne relation)

    Example:
        >>> user = User.objects.create_user(username='alice', password='secret')
        >>> # Signal fired automatically ↓
        >>> user.profile  # <UserProfile: Profile of alice>
        >>> user.profile.followers_count  # 0 (default value)

    Note:
        The created UserProfile has default values:
        - avatar: None (no image)
        - bio: "" (empty string)
        - followers_count: 0

    Database:
        This operation performs an INSERT in blog_userprofile table:
        INSERT INTO blog_userprofile (user_id, avatar_id, bio, followers_count)
        VALUES (user.id, NULL, '', 0)
    """
    # Check if it's a new creation (not an update)
    if created:
        # Create an empty UserProfile linked to this User
        # OneToOne relation: user.profile will be accessible
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal handler to sync UserProfile when a User is saved.

    This signal is triggered after every User save (creation OR update).
    It ensures modifications made to UserProfile via user.profile are
    properly persisted to database.

    Args:
        sender (Model class): The model class that emitted the signal (User)
        instance (User): The User instance that was just saved
        **kwargs: Additional signal arguments (created, using, update_fields, etc.)

    Behavior:
        - Checks that instance has a 'profile' attribute (avoids errors)
        - If profile exists: saves profile to database
        - If no profile: does nothing (rare case, normally create_user_profile
          should have created it)

    Safety:
        The hasattr() check is important because:
        - During first creation, create_user_profile() and save_user_profile()
          are called in order
        - If create_user_profile() fails, instance.profile wouldn't exist
        - hasattr() prevents an AttributeError

    Example:
        >>> user = User.objects.get(username='alice')
        >>> user.profile.bio = "Data Scientist"
        >>> user.profile.followers_count = 42
        >>> user.save()  # ← Triggers save_user_profile()
        >>> # Profile is now automatically saved

    Use Case:
        Allows saving profile by simply saving user:

        # Without this signal, you'd need to do:
        user.profile.bio = "..."
        user.profile.save()  # ← Explicit save required
        user.save()

        # With this signal:
        user.profile.bio = "..."
        user.save()  # ← Profile saved automatically

    Note:
        This signal is called on EVERY user.save(), even if profile hasn't changed.
        Django's update tracking handles optimization (no UPDATE if nothing changed).

    Database:
        This operation performs an UPDATE in blog_userprofile if fields changed:
        UPDATE blog_userprofile
        SET bio = '...', followers_count = ...
        WHERE user_id = instance.id
    """
    # Check that User has a profile (should always be the case)
    # hasattr() prevents AttributeError if profile doesn't exist
    if hasattr(instance, 'profile'):
        # Save profile to database
        # Django automatically detects modified fields
        instance.profile.save()
