from django.shortcuts import render, redirect


# Create your views here.
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not email or not password:
            pass
    return render(request, 'accounts/login.html')

def register_view(request):
    return render(request, 'accounts/register.html')

def logout_view(request):
    redirect('home')