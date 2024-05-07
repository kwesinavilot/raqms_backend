from rest_framework import serializers

class AuthSerializer(serializers.Serializer):
    userID = serializers.CharField(read_only=True)
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    phoneNumber = serializers.CharField()