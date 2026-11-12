from django.urls import path

from . import views

urlpatterns = [
    path("", views.show_home, name="home"),
    path("register/", views.register, name="register"),
    path("activate/<slug:token>/", views.activate, name="activate"),
    path("login/", views.sign_in, name="login"),
    path("login/2fa/", views.second_factor, name="second_factor"),
    path("logout/", views.sign_out, name="logout"),
    path("profile/", views.profile, name="profile"),
    path("profile/2fa/enable/", views.enable_2fa, name="enable_2fa"),
    path("profile/2fa/disable/", views.disable_2fa, name="disable_2fa"),
    path("forgot/", views.forgot, name="forgot"),
    path("reset/<slug:token>/", views.reset, name="reset"),
    path("manage/", views.dashboard, name="dashboard"),
    path("manage/<int:pk>/<str:action>/", views.change_account, name="change_account"),
    path("oidc/google/", views.google_start, name="google_start"),
    path("oidc/google/callback/", views.google_callback, name="google_callback"),
]
