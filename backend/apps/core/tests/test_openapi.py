from io import StringIO

from django.core.management import call_command


def test_openapi_schema_generates_without_warnings_or_errors(tmp_path):
    """Keeps the published API documentation complete as endpoints are added."""
    call_command("spectacular", "--validate", "--fail-on-warn", file=str(tmp_path / "schema.yml"), stderr=StringIO())
    text = (tmp_path / "schema.yml").read_text(encoding="utf-8")
    for path in ("/api/org/services/", "/api/org/security-policies/", "/api/org/security-policies/active/"):
        assert path in text
