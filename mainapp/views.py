from django.shortcuts import render
from django.http import JsonResponse
# from django.shortcuts import re
# Create your views here.
import json

from django.shortcuts import render

# Create your views here.
def index(request):
    return render(request, 'mainapp/index.html')


def apifunction(request):
    data = json.loads(request.body)
    print(f"data {data}")
    encryptionType = data['encryptionType']
    message = data['message']
    cryptmethod = data['type']
    return JsonResponse(data)
    if request.method == "POST":
        pass

        
    