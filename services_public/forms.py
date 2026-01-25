"""
Services Public Forms

Django forms for frontend search and filtering in the public service catalog.
"""

from django import forms


class ServiceSearchForm(forms.Form):
    """
    Frontend search and filter form for service catalog.

    Used in list view for filtering services.
    """

    # Search query
    q = forms.CharField(
        required=False,
        max_length=200,
        widget=forms.TextInput(attrs={
            'placeholder': 'Search services...',
            'class': 'input_search w-full h-full pl-10'
        }),
        label='Search'
    )

    # Category filter
    category = forms.CharField(
        required=False,
        max_length=100,
        widget=forms.Select(attrs={'class': 'w-full'}),
        label='Category'
    )

    # Location filters
    city = forms.CharField(
        required=False,
        max_length=100,
        widget=forms.Select(attrs={'class': 'w-full'}),
        label='City'
    )

    state = forms.CharField(
        required=False,
        max_length=100,
        label='State'
    )

    country = forms.CharField(
        required=False,
        max_length=100,
        label='Country'
    )

    # Price range
    min_price = forms.DecimalField(
        required=False,
        min_value=0,
        decimal_places=2,
        widget=forms.NumberInput(attrs={'placeholder': 'Min price'}),
        label='Minimum Price'
    )

    max_price = forms.DecimalField(
        required=False,
        min_value=0,
        decimal_places=2,
        widget=forms.NumberInput(attrs={'placeholder': 'Max price'}),
        label='Maximum Price'
    )

    # Rating filter
    min_rating = forms.DecimalField(
        required=False,
        min_value=0,
        max_value=5,
        decimal_places=1,
        label='Minimum Rating'
    )

    # Boolean filters
    verified = forms.BooleanField(
        required=False,
        label='Verified Providers Only'
    )

    remote = forms.BooleanField(
        required=False,
        label='Can Work Remotely'
    )

    accepting_work = forms.BooleanField(
        required=False,
        label='Currently Accepting Work'
    )

    # Service type
    service_type = forms.ChoiceField(
        required=False,
        choices=[
            ('', 'All Types'),
            ('fixed', 'Fixed Price'),
            ('hourly', 'Hourly Rate'),
            ('package', 'Package'),
        ],
        label='Service Type'
    )

    # Sorting
    sort = forms.ChoiceField(
        required=False,
        choices=[
            ('default', 'Featured'),
            ('rating', 'Highest Rated'),
            ('price_asc', 'Price: Low to High'),
            ('price_desc', 'Price: High to Low'),
            ('newest', 'Newest'),
            ('popular', 'Most Popular'),
        ],
        initial='default',
        label='Sort By'
    )

    # Pagination
    page = forms.IntegerField(
        required=False,
        min_value=1,
        widget=forms.HiddenInput(),
        label='Page'
    )


class ServiceMapFilterForm(ServiceSearchForm):
    """
    Extended search form for map view with geographic filters.

    Inherits from ServiceSearchForm and adds location-specific fields.
    """

    # Geographic center point
    lat = forms.DecimalField(
        required=False,
        decimal_places=6,
        widget=forms.HiddenInput(),
        label='Latitude'
    )

    lng = forms.DecimalField(
        required=False,
        decimal_places=6,
        widget=forms.HiddenInput(),
        label='Longitude'
    )

    # Search radius in kilometers
    radius = forms.IntegerField(
        required=False,
        min_value=1,
        max_value=500,
        initial=50,
        widget=forms.NumberInput(attrs={'placeholder': 'Radius (km)'}),
        label='Search Radius (km)'
    )

    def clean(self):
        """Validate that lat/lng are provided together."""
        cleaned_data = super().clean()
        lat = cleaned_data.get('lat')
        lng = cleaned_data.get('lng')

        if (lat and not lng) or (lng and not lat):
            raise forms.ValidationError(
                "Both latitude and longitude must be provided together."
            )

        return cleaned_data
