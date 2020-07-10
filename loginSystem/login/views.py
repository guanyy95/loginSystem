from django.shortcuts import render
from django.shortcuts import redirect
from django.conf import settings

from . import models
from . import form

import hashlib
import datetime

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
            if not user.has_confirmed:
                message = '用户邮箱未确认'
                return render(request, 'login/login.html', {'message' : message,
                                                            'login_form' : login_form})

            if user.password == hash_code(password):
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
    if request.session.get('is_login', None):
        return redirect('/index')

    if request.method == "POST":
        register_form = form.registerForm(request.POST)
        message = "检查填写内容"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            sex = register_form.cleaned_data.get('sex')

            if password1 != password2:
                message = "两次密码不同"
                return render(request, 'login/register.html', {'message': message,
                                                               'register_form' : register_form})
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = "用户名已经存在"
                    return render(request, 'login/register.html', {'message': message,
                                                               'register_form' : register_form})
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = "邮箱已经被注册"
                    return render(request, 'login/register.html', {'message': message,
                                                               'register_form' : register_form})

                new_user = models.User()
                new_user.name = username
                new_user.password = hash_code(password1)
                new_user.email = email
                new_user.sex = sex
                new_user.save()

                code = make_confirm_string(new_user)
                send_email(email, code)

                message = "请前往邮箱进行确认！"
                return render(request, 'login/confirm.html', {'message' : message, 'register_form' : register_form})
        else:
            return render(request, 'login/register.html', {'register_form' : register_form})
    register_form = form.registerForm()
    return render(request, 'login/register.html', {'register_form' : register_form})

def logout(request):
    if not request.session.get('is_login', None):
        return redirect("/login")
    request.session.flush()
    return redirect('/login')

def user_confirm(request):
    code = request.GET.get('code', None)
    if code:
        print("has code")
    message = ''

    try:
        confirm = models.ConfirmString.objects.get(code=code)
    except:
        message = "无效的确认请求"
        return render(request, 'login/confirm.html', {'message' : message})

    created_time = confirm.created_time
    now = datetime.datetime.now()

    if created_time + datetime.timedelta(settings.CONFIRM_DAYS) < now:
        confirm.user.delete()
        message = '邮件认证已经过期，请重新注册'
        return render(request, 'login/confirm.html', {'message': message})
    else:
        confirm.user.has_confirmed = True
        confirm.user.save()
        confirm.delete()
        message = '注册成功，请登录'
        return render(request, 'login/confirm.html', {'message': message})



"""
返回加盐后的md5摘要值
"""
def hash_code(s, salt='mysite'):
    md5 = hashlib.sha3_256()
    s = s + salt
    md5.update(s.encode())
    return md5.hexdigest()

def make_confirm_string(user):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code = hash_code(user.name, now)
    models.ConfirmString.objects.create(code=code, user=user, created_time=now)
    return code

def send_email(email, code):
    from django.core.mail import EmailMultiAlternatives

    subject = "来自guanyueyang@amberweather.com的注册邮件"

    text_content = '认证测试注册邮件的正文， 此文为非html文本'

    html_content = '''
                    <p>感谢注册<a href="http://{}/confirm/?code={}" target=blank>www.liujiangblog.com</a>，\
                    测试注册登录模块的链接</p>
                    <p>请点击站点链接完成注册确认！</p>
                    <p>此链接有效期为{}天！</p>
                    '''.format('127.0.0.1:8000', code, settings.CONFIRM_DAYS)
    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_HOST_USER, [email])
    msg.attach_alternative(html_content, "text/html")
    print("Successfully send Email")