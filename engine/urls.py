from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('blueprint/schema/', SpectacularAPIView.as_view(), name='blueprint.schema'),
    path('blueprint/docs/', SpectacularRedocView.as_view(url_name='blueprint.schema'), name='blueprint.redoc'),
    path('accounts/', include('accounts.urls')),
]
