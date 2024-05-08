from .views import *
from django.urls import path, include

urlpatterns = [
    path('current/', getLocationAQ, name='getLocationAQI'),
    path('history/', exposureHistory, name='exposureHistory'),
    path('history/all', getAllExposureHistory, name='getAllExposureHistory'),
]