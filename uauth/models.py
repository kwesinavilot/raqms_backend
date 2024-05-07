from django.db import models
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models import F
from accounts.models import User
from django.dispatch import receiver

class ResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    createdAt = models.DateTimeField(auto_now_add=True)

class FailedLogin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    count = models.IntegerField(default=0)
    createdAt = models.DateTimeField(auto_now_add=True)
    lastAttempt = models.DateTimeField(auto_now=True)

@receiver(user_logged_in)
def userLogInSuccessful(sender, request, user, **kwargs):
    """
    Triggered when a user successfully logs in. Used to delete failed login attempts.
    Args:
        sender: The sender of the signal.
        request: The request object.
        user: The user object who logged in.
        **kwargs: Additional keyword arguments.
    Returns:
        None
    """
    FailedLogin.objects.filter(user=user).delete()

@receiver(user_login_failed)
def userLogInFailed(sender, credentials, **kwargs):
    """
    Triggered when a user fails to log in. Used to increment the number of failed login attempts and deactivate user's account if necessary.
    Args:
        sender: The sender of the signal.
        credentials: The credentials of the failed login attempt.
        **kwargs: Additional keyword arguments.
    Returns:
        None
    """
    try:
        user = User.objects.get(email=credentials['email'])

        # Check if the user has any failed login records
        obj, created = FailedLogin.objects.get_or_create(user=user, defaults={'count': 1})

        if not created and obj.count >= 5:
            # Deactivate the user
            user.isBlocked = True
            user.save()
        else:
            # If the record already exists, increment the count
            obj.count = F('count') + 1
            obj.save()

    except User.DoesNotExist:
        # user does not exist, do nothing
        pass
