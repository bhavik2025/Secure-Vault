from .models import Notification


def notify(recipient, type_, title: str, message: str, *, priority=Notification.Priority.NORMAL, related_type="", related_id=""):
    """Create an in-app notification. Real-time push is added with the WebSocket module."""
    return Notification.objects.create(
        organization_id=recipient.organization_id,
        recipient=recipient,
        type=type_,
        title=title[:150],
        message=message[:500],
        priority=priority,
        related_type=related_type,
        related_id=str(related_id),
    )
