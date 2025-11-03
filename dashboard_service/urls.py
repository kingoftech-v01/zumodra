from django.urls import path
from .views import *

urlpatterns = [
    path('browse-service/', browse_service, name='browse_service'),
    path('browse-service/detail/<str:service_uuid>', browse_service_detail, name='browse_service_detail'),
    path('browse-nearby-service/', browse_nearby_services, name='browse_nearby_services'),
]

# <script>
# var map = L.map('map').setView([48.8566, 2.3522], 6);

# // Add OpenStreetMap tiles
# L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
#     attribution: '&copy; OpenStreetMap contributors'
# }).addTo(map);

# // Inject provider markers dynamically
# {% for provider in service_providers %}
#     {% if provider.location %}
#         L.marker([{{ provider.location.y }}, {{ provider.location.x }}])
#             .addTo(map)
#             .bindPopup("<b>{{ provider.user.username }}</b><br>{{ provider.address }}");
#     {% endif %}
# {% endfor %}
# </script>


# <link rel="stylesheet" href="{% static '/assets/css/leaflet.css' %}" />
        # <link rel="stylesheet" href="{% static '/assets/css/leaflet.css' %}" />
        #         <script src="{% static '/assets/js/leaflet.js' %}"></script>