from django.urls import path
from .views import user_registration, user_login, user_logout, update_password, token_refresh

urlpatterns = [
    path('register/', user_registration, name='user_registration'),
    path('login/', user_login, name='user_login'),
    path('logout/', user_logout, name='user_logout'),
    path('update_password/', update_password, name='update_password'),
    path('token_refresh/', token_refresh, name='token_refresh'),
]
