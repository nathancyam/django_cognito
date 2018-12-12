import json
from urllib import request

from django.http import HttpResponse, HttpRequest, JsonResponse
from jose import jwk, jwt
from jose.utils import base64url_decode

# Create your views here.


def index(request: HttpRequest) -> HttpResponse:
    return HttpResponse("Hi")


def login(request: HttpRequest) -> HttpResponse:
    if request.GET['id_token'] is None:
        return HttpResponse(status=400)

    token = request.GET['id_token']
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    key_index = -1
    jwks = get_jwks()
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


def get_jwks():
    region = 'ap-southeast-2'
    userpool_id = 'user_pool'
    keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
    response = request.urlopen(keys_url)
    return json.loads(response.read())['keys']
