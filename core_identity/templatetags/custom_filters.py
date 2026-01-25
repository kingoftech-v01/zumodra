"""
Custom template filters for custom_account_u app.

Provides utility filters for Django templates.
"""

from django import template

register = template.Library()


@register.filter(name='get_item')
def get_item(dictionary, key):
    """
    Get an item from a dictionary using a variable key.

    Usage in templates:
        {{ my_dict|get_item:my_key }}

    This is equivalent to: my_dict[my_key] in Python

    Args:
        dictionary: The dictionary to lookup
        key: The key to use for lookup

    Returns:
        The value from the dictionary, or None if key doesn't exist
    """
    if dictionary is None:
        return None
    return dictionary.get(key)
