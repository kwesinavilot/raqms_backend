from rest_framework import serializers
from .models import forecast

class ForecastSerializer(serializers.ModelSerializer):
    class Meta:
        model = forecast
        fields = '__all__'
        ordering = ['-created_at']