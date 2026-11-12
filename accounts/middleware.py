from django.contrib.auth import logout

from .security import restricted


class RestrictedAccountMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and restricted(request.user):
            logout(request)
        return self.get_response(request)
