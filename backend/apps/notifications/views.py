from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from .models import Notification
from .serializers import NotificationSerializer


class NotificationViewSet(ListModelMixin, GenericViewSet):
    """A user only ever sees their own notifications (filtered by recipient, not just organization)."""

    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    queryset = Notification.objects.all()

    def get_queryset(self):
        qs = Notification.objects.filter(recipient=self.request.user)
        if self.request.query_params.get("unread") in ("1", "true", "True"):
            qs = qs.filter(is_read=False)
        return qs

    @extend_schema(request=None, responses=NotificationSerializer)
    @action(detail=True, methods=["post"])
    def read(self, request, pk=None):
        note = self.get_object()
        if not note.is_read:
            note.is_read = True
            note.save(update_fields=["is_read"])
        return Response(NotificationSerializer(note).data)

    @extend_schema(request=None, responses=inline_serializer("MarkedRead", {"updated": serializers.IntegerField()}))
    @action(detail=False, methods=["post"], url_path="read-all")
    def read_all(self, request):
        return Response({"updated": self.get_queryset().update(is_read=True)})

    @extend_schema(responses=inline_serializer("UnreadCount", {"unread": serializers.IntegerField()}))
    @action(detail=False, methods=["get"], url_path="unread-count")
    def unread_count(self, request):
        return Response({"unread": Notification.objects.filter(recipient=request.user, is_read=False).count()})
