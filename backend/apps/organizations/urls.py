from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("org/departments", views.DepartmentViewSet, basename="department")

urlpatterns = [
    path("org/", views.OrganizationView.as_view(), name="organization"),
    path("", include(router.urls)),
]
