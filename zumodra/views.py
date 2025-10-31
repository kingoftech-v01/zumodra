from django.shortcuts import render
import os
from django.http import HttpResponse
from .settings import *

def home_view(request):
    return render(request, 'index.html')


# def js_dir_view(request, file_name):
#     file_path = os.path.join(STATICFILES_DIRS[0], 'assets','js', 'dir', file_name)
#     with open(file_path, 'rb') as f:
#         response = HttpResponse(f.read(), content_type="application/json")
#         response['Content-Disposition'] = f'inline; filename={file_name}'
#         return response

def js_dir_view(request, file_name):
<<<<<<< HEAD
    return render(request, f'static/js/dir/{file_name}', content_type="application/json")
=======
    return render(request, f'static/js/dir/{file_name}', content_type="application/json")

def auth_test_view(request):
    return render(request, 'authlab/sign-in.html')
>>>>>>> 5c8178b81147c1f40365b414172df210ed6b597d
