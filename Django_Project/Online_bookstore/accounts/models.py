from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.conf import settings

# ---------------------
# Custom User Manager
# ---------------------
class AppUserManager(BaseUserManager):
    def create_user(self, email, name, phone, address, gender, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field is mandatory')

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            name=name,
            phone=phone,
            address=address,
            gender=gender,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phone, address, gender, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if not password:
            raise ValueError("Superusers must have a password.")
        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self.create_user(email, name, phone, address, gender, password, **extra_fields)

# ---------------------
# Custom User Model
# ---------------------
class AppUser(AbstractUser):
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    )

    username = None  # Remove default username field
    email = models.EmailField(unique=True)

    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    address = models.TextField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)

    objects = AppUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone', 'address', 'gender']

    def __str__(self):
        return self.email

# ---------------------
# UserProfile Model
# ---------------------
def user_profile_picture_path(instance, filename):
    return f'profile_pics/user_{instance.user.id}/{filename}'

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    profile_picture = models.ImageField(
        upload_to=user_profile_picture_path,
        default='profile_pics/default_profile.png',
        blank=True,
        null=True
    )
    bio = models.TextField(blank=True, null=True)
    birth_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.name}'s Profile"
