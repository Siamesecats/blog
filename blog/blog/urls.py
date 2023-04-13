from django.contrib import admin
from django.urls import path,include

# 1.导入系统的 logging
# import logging
# # 2. 创建（获取）日志器
# logger = logging.getLogger('django')
# from django.http import HttpResponse
# def log(request):
# # 3. 使用日志器记录信息
#     logger.info('info')
#     return HttpResponse('test')

urlpatterns = [
    path('admin/', admin.site.urls),
    # include 参数1要设置为元组（urlconf_module, app_name）
    # namespace 设置命名空间
    path('', include(('users.urls', 'users'), namespace='users')),
    path('', include(('home.urls','home'),namespace='home')),
]
