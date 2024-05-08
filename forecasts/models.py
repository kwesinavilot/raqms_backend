from django.db import models
from accounts.models import User

# create a model to store the projected air quality forecasts
class forecast(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    location = models.CharField(max_length=255, help_text='City or location for the forecast')
    pm1 = models.FloatField(null=True, blank=True, help_text='Projected PM1 value')
    pm25 = models.FloatField(null=True, blank=True, help_text='Projected PM2.5 value')
    pm10 = models.FloatField(null=True, blank=True, help_text='Projected PM10 value')
    no2 = models.FloatField(null=True, blank=True, help_text='Projected NO2 value')
    aqi = models.FloatField(help_text='Projected overall AQI value')
    created_at = models.DateTimeField(auto_now_add=True, help_text='Date and time when the forecast was created')
    updated_at = models.DateTimeField(auto_now=True, help_text='Date and time when the forecast was last updated')

    def __str__(self):
        return f"UserID: {self.user.userID} - Lat: {self.latitude} - Long: {self.longitude} - PM2.5: {self.pm25} - AQI: {self.overallAQI} - Record Time: {self.recordTime}"