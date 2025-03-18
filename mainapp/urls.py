from django.urls import path, include
from .views import index, apifunction
urlpatterns = [
     path('', index),
     path('api', apifunction, name="api")
]
