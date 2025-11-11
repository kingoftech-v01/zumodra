from django.urls import path
from .views import *

urlpatterns = [
    path('services/', service_view, name='my_services'),
    path('add-service/', add_service_view, name='add_service'),
    path('service/<int:pk>', service_detail_view, name='service_detail'),
    path('service/<int:pk>/update', update_service_view, name='update_service'),
    path('service/<int:pk>/delete', delete_service_view, name='delete_service'),
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