from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.conf import settings

# user model
class User(AbstractUser):
    username = None
    id = None
    userID = models.CharField(_('User ID'), max_length=15, primary_key=True)
    firstName = models.CharField(_('First Name'), max_length=100)
    lastName = models.CharField(_('Last Name'), max_length=100)
    phoneNumber = models.CharField(_('Phone Number'), max_length=15)
    isActive = models.BooleanField(_('Active'), default=True)
    isBlocked = models.BooleanField(_('Blocked'), default=False)
    dateJoined = models.DateTimeField(auto_now_add=True)
    lastLogin = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'phoneNumber'
    REQUIRED_FIELDS = ['name']
    USERNAME = None

    def __str__(self):
        return f"{self.userID} - {self.name} - {self.phoneNumber} - active: {self.isActive} - joined: {self.dateJoined} - last login: {self.lastLogin}"


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def generate_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        token = Token.objects.create(user=instance)
        token.save()