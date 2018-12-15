import json
from os import environ
from urllib import request, parse
from base64 import b64encode

from jose import jwk, jwt
from jose.utils import base64url_decode

from django.http import HttpResponse, HttpRequest, JsonResponse
from django.views import View
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

# Create your views here.

AWS_REGION = environ['AWS_REGION']
COGNITO_DOMAIN = environ['AWS_COGNITO_DOMAIN']
COGNITO_CLIENT_ID = environ['AWS_COGNITO_CLIENT_ID']
COGNITO_CLIENT_SECRET = environ['AWS_COGNITO_CLIENT_SECRET']
COGNITO_USER_POOL = environ['AWS_COGNITO_USER_POOL']


class _UserInfo:
    def __init__(self, user_response: map, access_token: str):
        self.sub = user_response['sub']
        self.identities = json.loads(user_response['identities'])
        self.name = user_response['name']
        self.given_name = user_response['given_name']
        self.family_name = user_response['family_name']
        self.email = user_response['email']
        self.picture = user_response['picture']
        self.access_token = access_token


def index(req: HttpRequest) -> HttpResponse:
    return HttpResponse("Hi")


def _get_header() -> str:
    code = "{}:{}".format(COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)
    return b64encode(str.encode(code)).decode('utf-8')


def _get_user(code: str) -> _UserInfo:
    data = parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": "http://localhost:8000/cognito/login",
        "code": code
    }).encode()

    url = "https://{}/oauth2/token".format(COGNITO_DOMAIN)

    req = request.Request(url, data=data, headers={
        "Authorization": "Basic {}".format(_get_header()),
        "Content-Type": "application/x-www-form-urlencoded"
    })

    response = request.urlopen(req)
    auth = json.loads(response.read())
    access_token = auth['access_token']

    url = "https://{}/oauth2/userInfo".format(COGNITO_DOMAIN)

    req = request.Request(url, headers={
        "Authorization": "Bearer {}".format(access_token)
    })

    response = request.urlopen(req)
    user_details = json.loads(response.read())
    return _UserInfo(user_details, access_token)


class JWTLoginView(View):
    jwk = None
    keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(AWS_REGION, COGNITO_USER_POOL)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        JWTLoginView.__get_jwks()

    # noinspection PyMethodMayBeStatic
    def get(self, req: HttpRequest) -> HttpResponse:
        if req.GET['id_token'] is None:
            return HttpResponse(status=400)

        token = req.GET['id_token']
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']

        key_index = -1
        jwks = self.jwk
        for i in range(len(jwks)):
            if kid == jwks[i]['kid']:
                key_index = i
                break

        if key_index == -1:
            print('Public key not found in jwks.json')
            return HttpResponse(status=400)

        public_key = jwk.construct(jwks[key_index])
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            print('Signature verification failed')
            return HttpResponse(status=400)

        claims = jwt.get_unverified_claims(token)
        print(claims)
        return JsonResponse(claims)

    @classmethod
    def __get_jwks(cls):
        if cls.jwk is not None:
            return

        response = request.urlopen(cls.keys_url)
        cls.jwk = json.loads(response.read())['keys']


class LoginView(View):

    def get(self, req: HttpRequest) -> HttpResponse:
        if req.GET['code'] is None:
            return HttpResponse(status=400)

        test = _get_user(req.GET['code'])

        try:
            User.objects.get(email=test.email)
        except ObjectDoesNotExist:
            User.objects.create_user(test.email, email=test.email, first_name=test.given_name,
                                     last_name=test.family_name)
        except MultipleObjectsReturned:
            return JsonResponse({"error": "Multiple users for this email"}, status=400)

        return JsonResponse({"status": "OK", "token": test.access_token})
