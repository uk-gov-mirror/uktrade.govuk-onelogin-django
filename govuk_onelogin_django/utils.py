import base64
import json
import logging
from importlib import import_module
from typing import Any, Self

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt as authlib_jwt
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from authlib.oidc.core import IDToken
from django.conf import settings
from django.core.cache import cache
from django.http import QueryDict
from django.urls import reverse
from joserfc import jwt

from . import types

logger = logging.getLogger(__name__)
TOKEN_SESSION_KEY = "_one_login_token"


def get_client(request: types.DjangoHttpRequest) -> OAuth2Session:
    callback_url = reverse("one_login:callback")
    redirect_uri = request.build_absolute_uri(callback_url)

    # One Login admin tool doesn't support setting http://127.0.0.1 as a redirect url.
    if redirect_uri.startswith("http://127.0.0.1"):
        redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost")

    session = OAuth2Session(
        client_id=get_client_id(request),
        client_secret=get_secret(request),
        token_endpoint_auth_method="private_key_jwt",
        redirect_uri=redirect_uri,
        scope=get_scope(),
        token=request.session.get(TOKEN_SESSION_KEY, None),
    )

    return session


class OneLoginConfig:
    CACHE_KEY = "one_login_metadata_cache"
    CACHE_EXPIRY = 60 * 60  # seconds

    def __init__(self) -> None:
        self._conf: dict[str, Any] = {}

    def get_public_keys(self) -> list[dict[str, str]]:
        # https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/authenticate-your-user/#validate-your-id-token
        resp = requests.get(self.openid_config["jwks_uri"])
        resp.raise_for_status()
        data = resp.json()

        return data["keys"]

    @property
    def openid_config(self) -> dict[str, Any]:
        # Cached on instance
        if self._conf:
            logger.debug("one login conf: using instance attribute")
            return self._conf

        # Cached in redis store
        cache_config = cache.get(self.CACHE_KEY)
        if cache_config:
            logger.debug("one login conf: using cache value")
            self._conf = json.loads(cache_config)
            return self._conf

        # Retrieve and store value
        config = self._get_configuration()
        cache.set(self.CACHE_KEY, json.dumps(config), timeout=self.CACHE_EXPIRY)
        self._conf = config
        logger.debug("one login conf: using fresh value")

        return self._conf

    def _get_configuration(self) -> dict[str, Any]:
        resp = requests.get(settings.GOV_UK_ONE_LOGIN_OPENID_CONFIG_URL)
        resp.raise_for_status()
        metadata = resp.json()

        return metadata

    @property
    def authorise_url(self) -> str:
        return self.openid_config["authorization_endpoint"]

    @property
    def token_url(self) -> str:
        return self.openid_config["token_endpoint"]

    @property
    def userinfo_url(self) -> str:
        return self.openid_config["userinfo_endpoint"]

    @property
    def end_session_url(self) -> str:
        return self.openid_config["end_session_endpoint"]

    @property
    def issuer(self) -> str:
        return self.openid_config["issuer"]


def get_token(request: types.DjangoHttpRequest, auth_code: str) -> dict:
    client = get_client(request)
    config = get_oidc_config()

    client.register_client_auth_method(PrivateKeyJWT(token_endpoint=config.token_url))

    # https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/authenticate-your-user/#receive-response-for-make-a-token-request
    token = client.fetch_token(
        url=config.token_url,
        code=auth_code,
        # If you’re requesting a refresh token, you must set this parameter to refresh_token.
        # Otherwise, you need to set the parameter to authorization_code.
        grant_type="authorization_code",
    )

    validate_token(request, token)

    return token


class IDTokenJWTClaimsRegistry(jwt.JWTClaimsRegistry):
    """Subclass of JWTClaimsRegistry to check extra claims.

    Keys checked by jwt.JWTClaimsRegistry:
      - iss
      - sub
      - aud
      - exp
      - nbf
      - iat
    Extra keys we could check:
      - at_hash
      - vot
      - vtm
      - sid
      - auth_time
    """

    # example_values = {
    #     "at_hash": "ZDevf74CkYWNPa8qmflQyA",
    #     "vot": "Cl.Cm",
    #     "vtm": "https://oidc.integration.account.gov.uk/trustmark",
    #     "sid": "dX5xv0XgHh6yfD1xy-ss_1EDK0I",
    #     "auth_time": 1704894300,
    #     "sub": "urn:fdc:gov.uk:2022:VtcZjnU4Sif2oyJZola3OkN0e3Jeku1cIMN38rFlhU4",  # checked
    #     "aud": "{YOUR_CLIENT_ID}",  # checked
    #     "iss": "https://oidc.integration.account.gov.uk/",  # checked
    #     "exp": 1704894526,  # checked
    #     "iat": 1704894406,  # checked
    #     "nonce": "lZk16Vmu8-h7r8L8bFFiHJxpC3L73UBpfb68WC1Qoqg",  # checked
    # }

    @classmethod
    def from_config(
        cls,
        iss_value: str,
        aud_value: str,
        nonce_value: str,
    ) -> Self:
        claim_options: dict[str, jwt.ClaimsOption] = {
            "iss": jwt.ClaimsOption(essential=True, value=iss_value),
            "aud": jwt.ClaimsOption(essential=True, value=aud_value),
            "nonce": jwt.ClaimsOption(essential=True, value=nonce_value),
        }
        return cls(**claim_options)

    def validate_at_hash(self, value: str) -> None:
        """OPTIONAL. Access Token hash value. Its value is the base64url
        encoding of the left-most half of the hash of the octets of the ASCII
        representation of the access_token value, where the hash algorithm
        used is the hash algorithm used in the alg Header Parameter of the
        ID Token's JOSE Header. For instance, if the alg is RS256, hash the
        access_token value with SHA-256, then take the left-most 128 bits and
        base64url encode them. The at_hash value is a case sensitive string.
        """
        # TODO: Check if we can rely on these imports
        # from joserfc.errors import InvalidClaimError
        # import hmac
        # from authlib.common.encoding import to_bytes
        # from authlib.oidc.core.util import create_half_hash
        #
        #
        # def _verify_hash(signature, s, alg):
        #     hash_value = create_half_hash(s, alg)
        #     if hash_value is None:
        #         return False
        #     return hmac.compare_digest(hash_value, to_bytes(signature))
        #
        # access_token = self.params.get("access_token")
        # access_token = "asdf"
        # at_hash = self.get("at_hash")
        # if at_hash and access_token:
        #     # TODO: get the algorithm / token
        #     if not _verify_hash(at_hash, access_token, self.header["alg"]):
        #         raise InvalidClaimError("at_hash")
        return

    def validate_auth_time(self, value: str) -> None:
        # """Time when the End-User authentication occurred. Its value is a JSON
        # number representing the number of seconds from 1970-01-01T0:0:0Z as
        # measured in UTC until the date/time. When a max_age request is made or
        # when auth_time is requested as an Essential Claim, then this Claim is
        # REQUIRED; otherwise, its inclusion is OPTIONAL.
        # """
        # auth_time = self.get("auth_time")
        # if self.params.get("max_age") and not auth_time:
        #     raise MissingClaimError("auth_time")
        #
        # if auth_time and not isinstance(auth_time, (int, float)):
        #     raise InvalidClaimError("auth_time")

        return None

    def validate_sid(self, value: str) -> None:
        # 	sid stands for ‘session identifier’. This uniquely identifies the user’s journey within GOV.UK One Login.
        return None

    def validate_vot(self, value: str) -> None:
        # vot stands for ‘Vector of Trust’.
        return None

    def validate_vtm(self, value: str) -> None:
        # 	vtm stands for ‘vector trust mark’.
        # 	This is an HTTPS URL which lists the range of values GOV.UK One Login accepts and provides.
        return None


def validate_token(request: types.DjangoHttpRequest, token: dict[str, Any]) -> None:
    print("Incoming token:")
    print(token)

    config = get_oidc_config()
    stored_nonce = get_oauth_nonce(request)

    # id_token contents:
    # https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/authenticate-your-user/#understand-your-id-token
    signed_jwt = token["id_token"]  # The JWT to decode
    key = config.get_public_keys()
    print("Signing key:")
    print(key)

    #
    # Old way to validate ID token
    #
    claims = authlib_jwt.decode(
        signed_jwt,
        key,
        claims_cls=IDToken,
        claims_options={
            "iss": {"essential": True, "value": config.issuer},
            "aud": {"essential": True, "value": get_client_id(request)},
        },
        claims_params={"nonce": stored_nonce},
    )
    claims.validate()

    #
    # New way to validate ID token
    #
    decoded_token = jwt.decode(signed_jwt, key)
    print("TOKEN STUFF:")
    print(decoded_token.header)
    print(decoded_token.claims)

    claims_requests = IDTokenJWTClaimsRegistry.from_config(
        iss_value=config.issuer,
        aud_value=get_client_id(request),
        nonce_value=stored_nonce,
    )
    claims_requests.validate(decoded_token.claims)


def get_userinfo(client: OAuth2Session) -> types.UserInfo:
    config = get_oidc_config()
    resp = client.get(config.userinfo_url)
    resp.raise_for_status()

    return resp.json()


def has_valid_token(client: OAuth2Session) -> bool:
    return client.token is not None


def store_oauth_state(request: types.DjangoHttpRequest, state: str) -> None:
    request.session[f"{TOKEN_SESSION_KEY}_oauth_state"] = state


def get_oauth_state(request: types.DjangoHttpRequest) -> str | None:
    return request.session.get(f"{TOKEN_SESSION_KEY}_oauth_state", None)


def delete_oauth_state(request: types.DjangoHttpRequest) -> None:
    request.session.delete(f"{TOKEN_SESSION_KEY}_oauth_state")


def store_oauth_nonce(request: types.DjangoHttpRequest, nonce: str) -> None:
    request.session[f"{TOKEN_SESSION_KEY}_oauth_nonce"] = nonce


def get_oauth_nonce(request: types.DjangoHttpRequest) -> str | None:
    return request.session.get(f"{TOKEN_SESSION_KEY}_oauth_nonce", None)


def delete_oauth_nonce(request: types.DjangoHttpRequest) -> None:
    request.session.delete(f"{TOKEN_SESSION_KEY}_oauth_nonce")


def get_secret(request: types.DjangoHttpRequest) -> bytes:
    # key is stored like this: base64 -i private_key.pem so decode.
    return base64.b64decode(get_client_secret(request))


def get_scope():
    return getattr(settings, "GOV_UK_ONE_LOGIN_SCOPE", "openid email")


def get_client_id(request: types.DjangoHttpRequest) -> str:
    """Fetch the client id in one of two ways.

    1. Using a function called get_one_login_client_id defined in the module specified at
       GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH setting.
    2. Returning the value found in GOV_UK_ONE_LOGIN_CLIENT_ID setting.
    """

    if path := getattr(settings, "GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH", None):
        config_utils = import_module(path)

        if hasattr(config_utils, "get_one_login_client_id"):
            logger.debug(f"Using {path} to find get_one_login_client_id function.")
            return config_utils.get_one_login_client_id(request)

    logger.debug("Using GOV_UK_ONE_LOGIN_CLIENT_ID to find client secret.")

    # Default if custom function not defined
    return getattr(settings, "GOV_UK_ONE_LOGIN_CLIENT_ID", "")


def get_oidc_config() -> OneLoginConfig:
    """Fetch the OneLoginConfig class in one of two ways.

    1. Using a function called get_one_login_config defined in the module specified at
       GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH setting.
    2. Returning the default OneLoginConfig class.
    """

    if path := getattr(settings, "GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH", None):
        config_utils = import_module(path)

        if hasattr(config_utils, "get_one_login_config"):
            CustomConfigCls = config_utils.get_one_login_config()

            logger.debug(f"Using custom {CustomConfigCls!r} class.")

            return CustomConfigCls()

    logger.debug("Using default OneLoginConfig class.")

    # Default if custom class not defined
    return OneLoginConfig()


def get_client_secret(request: types.DjangoHttpRequest) -> str:
    """Fetch the client secret in one of two ways.

    1. Using a function called get_one_login_client_secret defined in the module specified at
       GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH setting.
    2. Returning the value found in GOV_UK_ONE_LOGIN_CLIENT_SECRET setting.
    """

    if path := getattr(settings, "GOV_UK_ONE_LOGIN_GET_CLIENT_CONFIG_PATH", None):
        config_utils = import_module(path)

        if hasattr(config_utils, "get_one_login_client_secret"):
            logger.debug(f"Using {path} to find get_one_login_client_secret function.")
            return config_utils.get_one_login_client_secret(request)

    logger.debug("Using GOV_UK_ONE_LOGIN_CLIENT_SECRET to find client secret.")

    # Default if custom function not defined
    return getattr(settings, "GOV_UK_ONE_LOGIN_CLIENT_SECRET", "")


def get_one_login_logout_url(
    request: types.DjangoHttpRequest, post_logout_redirect_uri: str | None = None
) -> str:
    """Get logout url for logging a user out of GOV.UK One Login.

    https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/managing-your-users-sessions/#log-your-user-out-of-gov-uk-one-login

    :param request: Django HttpRequest instance
    :param post_logout_redirect_uri: Optional redirect url
    """
    config = get_oidc_config()
    url = config.end_session_url

    if post_logout_redirect_uri:
        qd = QueryDict(mutable=True)
        qd.update(
            {
                "id_token_hint": request.session[TOKEN_SESSION_KEY]["id_token"],
                "post_logout_redirect_uri": post_logout_redirect_uri,
            }
        )
        url = f"{url}?{qd.urlencode()}"

    return url
