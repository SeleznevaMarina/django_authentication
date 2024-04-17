from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import User, RefreshToken

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'username': 'test_user',
            'password': 'test_password'
        }
        self.user = User.objects.create_user(**self.user_data)
        self.token = RefreshToken.objects.create(user=self.user, token='test_token', expires_at=None)

    def test_user_registration(self):
        response = self.client.post(reverse('user_registration'), data=self.user_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_login(self):
        response = self.client.post(reverse('user_login'), data=self.user_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('refresh_token', response.data)

    def test_user_logout(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('user_logout'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_password(self):
        new_password = 'new_test_password'
        self.client.force_authenticate(user=self.user)
        response = self.client.post(reverse('update_password'), data={'new_password': new_password})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_token_refresh(self):
        response = self.client.post(reverse('token_refresh'), data={'refresh_token': self.token.token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
