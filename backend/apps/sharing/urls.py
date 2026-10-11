from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("vault/access-requests", views.AccessRequestViewSet, basename="access-request")

urlpatterns = [
    path("vault/credentials/<int:credential_id>/shares/", views.CredentialShareView.as_view(), name="credential-shares"),
    path("vault/credentials/<int:credential_id>/shares/tree/", views.CredentialShareTreeView.as_view(), name="credential-share-tree"),
    path("vault/shares/<int:pk>/revoke/", views.ShareRevokeView.as_view(), name="share-revoke"),
    path("vault/shared-with-me/", views.SharedWithMeView.as_view(), name="shared-with-me"),
    path("vault/shared-by-me/", views.SharedByMeView.as_view(), name="shared-by-me"),
    path("", include(router.urls)),
]
