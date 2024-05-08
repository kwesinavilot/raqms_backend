from rest_framework import serializers
from .models import AQReadings

class AQReadingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AQReadings
        fields = '__all__'

class AQHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AQReadings
        fields = ['recordTime', 'pm25', 'temperature', 'humidity', 'overallAQI']