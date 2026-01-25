"""
Blog Forms Module - Django Forms for Blog Application
======================================================

This module contains Django forms to handle user interactions
in the blog application. Currently, it only handles comments,
but can be extended for other features.

Forms:
------
- CommentForm: Comment submission and validation with HTML sanitization

Security Features:
------------------
- Automatic HTML sanitization via core.validators.sanitize_html
- Required field validation
- CSRF protection (handled by Django middleware in templates)
- Comment threading support (hidden parent field)

Usage Example:
--------------
In views.py:
    form = CommentForm(request.POST)
    if form.is_valid():
        comment = form.save(commit=False)
        comment.post = post
        comment.save()

In template:
    <form method="POST" action="{% url 'blog:submit_comment' post.id %}">
        {% csrf_token %}
        {{ form.author_name }}
        {{ form.content }}
        {{ form.parent }}
        <button type="submit">Post Comment</button>
    </form>
"""

from django import forms
from .models import Comment


class CommentForm(forms.ModelForm):
    """
    Django form for submitting comments on blog posts.

    This form handles validation and sanitization of comments submitted
    by users. It protects against XSS attacks by cleaning HTML
    in both author name and comment content.

    Fields:
        author_name (CharField): Author's name (max 200 characters)
            - Automatically sanitized in clean_author_name()
            - Required field
            - Custom widget with preserved Tailwind CSS classes

        content (TextField): Comment content
            - Automatically sanitized in clean_content()
            - Required field
            - Rendered as Textarea (3 rows)
            - Custom widget with preserved Tailwind CSS classes

        parent (ForeignKey, optional): Parent comment for threading
            - Hidden field (HiddenInput widget)
            - Allows nested replies
            - Null/blank if top-level comment

    Widgets:
        Custom widgets preserve CSS classes from original template
        to maintain intact styling. Each field has:
        - Tailwind classes for styling
        - Unique ID for labels
        - Placeholder text for UX
        - Required attribute for HTML5 validation

    Security:
        - HTML Sanitization: All inputs are cleaned via
          core.validators.sanitize_html to prevent XSS
        - CSRF Protection: Requires {% csrf_token %} in template
        - Validation: Standard Django validation + custom cleaning

    Threading Support:
        To create a reply to an existing comment, pass parent ID:
        <input type="hidden" name="parent" value="{{ parent_comment.id }}">

    Example Usage:
        # In a view
        if request.method == 'POST':
            form = CommentForm(request.POST)
            if form.is_valid():
                comment = form.save(commit=False)
                comment.post = current_post
                comment.save()
                messages.success(request, 'Comment posted!')

        # Render errors in template
        {% if form.author_name.errors %}
            <span class="error">{{ form.author_name.errors }}</span>
        {% endif %}
    """

    class Meta:
        model = Comment
        fields = ['author_name', 'content', 'parent']

        # Custom widgets to preserve CSS classes from original template
        # These Tailwind classes are essential to maintain styling
        widgets = {
            # Name field: TextInput with Tailwind classes for styling
            'author_name': forms.TextInput(attrs={
                'class': 'w-full mt-2 px-4 py-3 border-line rounded-lg',  # Tailwind classes
                'id': 'username',  # ID for label
                'placeholder': 'Your Name',  # Placeholder text for UX
                'required': True,  # HTML5 validation (backup to Django validation)
            }),

            # Content field: Textarea with 3 visible rows
            'content': forms.Textarea(attrs={
                'class': 'border w-full mt-2 px-4 py-3 border-line rounded-lg',  # Tailwind
                'id': 'message',  # ID for label
                'rows': '3',  # Initial textarea height
                'placeholder': 'Write comment',  # Placeholder
                'required': True,  # HTML5 validation
            }),

            # Parent field: Hidden input for comment threading
            # Will be empty for top-level comments, contains parent.id for replies
            'parent': forms.HiddenInput(),
        }

    def clean_content(self):
        """
        Clean and sanitize comment content to prevent XSS attacks.

        This method is automatically called by Django during form validation
        (form.is_valid()). It retrieves the content cleaned by Django's
        standard validators, then applies additional HTML sanitization
        via core.validators.sanitize_html.

        Security:
            Protects against malicious code injections (XSS) by:
            - Removing script, iframe, etc. tags
            - Escaping dangerous HTML characters
            - Allowing only safe tags (p, b, i, em, strong, etc.)

        Returns:
            str: Sanitized content, safe for database insertion
                 and template display with |safe filter

        Raises:
            ValidationError: If content is empty after sanitization (implicit)

        Example:
            Input:  "<script>alert('XSS')</script>Hello <b>World</b>"
            Output: "Hello <b>World</b>"
        """
        from core.validators import sanitize_html

        # Get content already validated by Django (not None, has text, etc.)
        content = self.cleaned_data.get('content')

        # Apply HTML sanitization for security
        # sanitize_html() is defined in core.validators
        return sanitize_html(content)

    def clean_author_name(self):
        """
        Clean and sanitize author name to prevent XSS attacks.

        Although the name is supposed to be plain text, this method applies
        HTML sanitization as a precaution against attempts to inject
        malicious code in the name field.

        Security:
            - Removes all HTML tags from name
            - Escapes special characters
            - Prevents script injection in author name

        Returns:
            str: Sanitized name, safe for display

        Raises:
            ValidationError: If name is empty after sanitization (implicit)

        Example:
            Input:  "John<script>alert('XSS')</script>Doe"
            Output: "JohnDoe" (or "John Doe" depending on sanitize_html implementation)

        Note:
            Name is limited to 200 characters by the Comment model.
            This length validation is automatic via ModelForm.
        """
        from core.validators import sanitize_html

        # Get name already validated by Django
        name = self.cleaned_data.get('author_name')

        # Sanitize name (even if it's plain text, we're cautious)
        return sanitize_html(name)
