from .views import *
from django.urls import path, include

urlpatterns = [
    path('week/', getWeeklyForecast, name='weeklyForecast'),
    path('hourly/', getHourlyForecast, name='hourlyForecast'),
]