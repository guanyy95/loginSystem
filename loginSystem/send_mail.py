import os
from django.core.mail import send_mail

os.environ['DJANGO_SETTINGS_MODULE'] = 'loginSystem.settings'

if __name__ == '__main__':
    send_mail(
        '测试标题',
        '测试内容文本',
        'guanyueyang@amberweather.com',
        ['707956197@qq.com'],
    )