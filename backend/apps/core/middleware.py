import uuid


class RequestIDMiddleware:
    """Assigns a server-generated correlation ID to every request.

    A client-supplied ID is deliberately ignored: it could be used to forge or collide
    audit correlation IDs. The ID is echoed in `X-Request-ID` so support can trace a call.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = str(uuid.uuid4())
        response = self.get_response(request)
        response["X-Request-ID"] = request.request_id
        return response
