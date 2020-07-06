from django.shortcuts import render
from django.shortcuts import redirect
from django.views import debug
from . import models
from . import form

def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    else:
        return render(request, 'login/index.html')

def login(request):
    if request.session.get('is_login', None):
        return redirect('/index/')
    if request.method == "POST":
        login_form = form.UserForm(request.POST)
        message = "请检查填写的内容"
        if login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')
            try:
                user = models.User.objects.get(name=username)
            except:
                message = '用户不存在！'
                return render(request, 'login/login.html', {'message' : message,
                                                            'login_form' : login_form})

            if user.password == password:
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
            else:
                message = "密码不正确"
                return render(request, 'login/login.html', {'message' : message,
                                                            'login_form' : login_form})
        else:
            return render(request, 'login/login.html', {'message' : message,
                                                            'login_form' : login_form})
    else:#使用get方法
        login_form = form.UserForm()
        return render(request, 'login/login.html', {"login_form" : login_form})

def register(request):

    return render(request, 'login/register.html')

def logout(request):
    if not request.session.get('is_login', None):
        return redirect("login/")
    request.session.flush()
    return redirect('/login')