import pytest

from apps.notifications.models import Notification
from apps.notifications.services import notify

pytestmark = pytest.mark.django_db
URL = "/api/notifications/"


def make(user, n=1, **kw):
    return [notify(user, Notification.Type.SHARE_RECEIVED, f"Title {i}", "Body", **kw) for i in range(n)]


def test_users_only_see_their_own_notifications(api_as, make_user, org_a, org_b):
    me, colleague, outsider = make_user(org_a), make_user(org_a), make_user(org_b)
    make(me, 2), make(colleague, 3), make(outsider, 1)
    body = api_as(me).get(URL).json()
    assert body["count"] == 2 and all(n["title"].startswith("Title") for n in body["results"])
    assert body["results"][0]["id"] > body["results"][1]["id"]  # newest first


def test_mark_read_unread_filter_and_count(api_as, make_user, org_a):
    me = make_user(org_a)
    first, second = make(me, 2)
    c = api_as(me)
    assert c.get(URL + "unread-count/").json() == {"unread": 2}
    assert c.post(f"{URL}{first.pk}/read/").json()["is_read"] is True
    assert c.post(f"{URL}{first.pk}/read/").status_code == 200  # idempotent
    assert [n["id"] for n in c.get(URL + "?unread=true").json()["results"]] == [second.pk]
    assert c.get(URL + "unread-count/").json() == {"unread": 1}


def test_read_all_only_touches_my_notifications(api_as, make_user, org_a):
    me, other = make_user(org_a), make_user(org_a)
    make(me, 3)
    make(other, 2)
    assert api_as(me).post(URL + "read-all/").json() == {"updated": 3}
    assert Notification.objects.filter(recipient=other, is_read=False).count() == 2


def test_cannot_read_or_mark_someone_elses_notification(api_as, make_user, org_a):
    me, other = make_user(org_a), make_user(org_a)
    (note,) = make(other)
    assert api_as(me).post(f"{URL}{note.pk}/read/").status_code == 404
    note.refresh_from_db()
    assert note.is_read is False


def test_anonymous_is_rejected(api):
    assert api.get(URL).status_code == 403


def test_messages_are_truncated_and_carry_the_recipients_organization(make_user, org_a):
    me = make_user(org_a)
    n = notify(me, Notification.Type.SHARE_REVOKED, "t" * 500, "m" * 900)
    assert len(n.title) == 150 and len(n.message) == 500 and n.organization_id == org_a.id
