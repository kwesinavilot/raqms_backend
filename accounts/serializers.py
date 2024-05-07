from rest_framework import serializers
from .models import User

# create a user serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class AuthSerializer(serializers.Serializer):
    userID = serializers.CharField(read_only=True)
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    phoneNumber = serializers.CharField()