from django.db import models
from django.contrib.auth.models import AbstractUser, Permission, Group
from django.utils import timezone

class User(AbstractUser):
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.username
    
    user_permissions = models.ManyToManyField(
        Permission,
        through='UserPermission',
        related_name='my_app_user_permissions'
    )
    groups = models.ManyToManyField(
        Group,
        related_name='my_app_user_groups'
    )

    class UserPermission(models.Model):
        user = models.ForeignKey('User', on_delete=models.CASCADE)
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            db_table = 'my_app_user_permission'

class RefreshToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

class MyModel(models.Model):
    user = models.ManyToManyField(User, related_name='my_model_groups')