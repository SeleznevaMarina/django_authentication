from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import update_last_login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.authtoken.models import Token
from datetime import timedelta
from django.utils import timezone
import jwt
from django.conf import settings

from .models import User, RefreshToken
from .serializers import UserSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def user_registration(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'User registered successfully'}, status=HTTP_200_OK)
    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)
        token, _ = Token.objects.get_or_create(user=user)
        refresh_token = RefreshToken.objects.create(user=user, token=uuid.uuid4(), expires_at=timezone.now() + timedelta(days=settings.REFRESH_TOKEN_LIFESPAN_DAYS))
        return JsonResponse({'token': token.key, 'refresh_token': refresh_token.token}, status=HTTP_200_OK)
    return JsonResponse({'error': 'Invalid credentials'}, status=HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    logout(request)
    return JsonResponse({'message': 'User logged out successfully'}, status=HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_password(request):
    user = request.user
    new_password = request.data.get('new_password')
    user.set_password(new_password)
    user.save()
    return JsonResponse({'message': 'Password updated successfully'}, status=HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def token_refresh(request):
    refresh_token = request.data.get('refresh_token')
    if refresh_token:
        try:
            refresh_token_obj = RefreshToken.objects.get(token=refresh_token)
            if refresh_token_obj.expires_at >= timezone.now():
                user = refresh_token_obj.user
                token, _ = Token.objects.get_or_create(user=user)
                refresh_token_obj.expires_at = timezone.now() + timedelta(days=settings.REFRESH_TOKEN_LIFESPAN_DAYS)
                refresh_token_obj.save()
                return JsonResponse({'token': token.key}, status=HTTP_200_OK)
            else:
                return JsonResponse({'error': 'Refresh token expired'}, status=HTTP_400_BAD_REQUEST)
        except RefreshToken.DoesNotExist:
            return JsonResponse({'error': 'Invalid refresh token'}, status=HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({'error': 'Refresh token not provided'}, status=HTTP_400_BAD_REQUEST)
