from django.urls import path, include
from .views import decrypt, encrypt, index
urlpatterns = [
     path('', index),
     path('api/encrypt', encrypt, name="api"),
     path('api/decrypt', decrypt)
]
