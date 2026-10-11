from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("vault/credentials", views.CredentialViewSet, basename="credential")
router.register("vault/notes", views.SecureNoteViewSet, basename="secure-note")

urlpatterns = [
    path("vault/password/generate/", views.PasswordGenerateView.as_view(), name="password-generate"),
    path("vault/password/check/", views.PasswordCheckView.as_view(), name="password-check"),
    path("", include(router.urls)),
]
