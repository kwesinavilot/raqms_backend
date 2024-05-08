from django.db import models
from accounts.models import User

# create a model to store user's location and the air quality readings around them
class AQReadings(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    latitude = models.FloatField(max_length=8, null=False)
    longitude = models.FloatField(max_length=8, null=False)
    pm1 = models.FloatField(max_length=5, null=True, blank=True)
    pm25 = models.FloatField(max_length=5, null=True, blank=True)
    pm10 = models.FloatField(max_length=5, null=True, blank=True)
    no2 = models.FloatField(max_length=5, null=True, blank=True)
    humidity = models.FloatField()
    temperature = models.FloatField(max_length=5, null=True, blank=True)
    overallAQI = models.FloatField()
    recordTime = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"UserID: {self.user.userID} - Lat: {self.latitude} - Long: {self.longitude} - PM2.5: {self.pm25} - AQI: {self.overallAQI} - Record Time: {self.recordTime}"