from django.urls import path
from users.views import RegisterView,ImageCodeView,SmsCodeView,LoginView,LogoutView,ForgetPasswordView,UserCenterView,WriteBlogView

urlpatterns = [
    # 注册
    path('register/',RegisterView.as_view(),name='register'),
    # 图片验校检码
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),
    # 信息验证码
    path('smscode/', SmsCodeView.as_view(), name='smscode'),
    # 登录
    path('login/', LoginView.as_view(), name='login'),
    # 退出登录
    path('logout/', LogoutView.as_view(), name='logout'),
    # 忘记密码
    path('forgetpassword/', ForgetPasswordView.as_view(), name='forgetpassword'),
    # 个人中心
    path('center/', UserCenterView.as_view(), name='center'),
    # 博客
    path('writeblog/', WriteBlogView.as_view(), name='writeblog'),

]
# 图片访问的路由
from django.conf import settings
from django.conf.urls.static import static
urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)