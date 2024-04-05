---
title: "OAuth 2.0 for First-Party Applications"
abbrev: "OAuth for First-Party Apps"
category: std

docname: draft-parecki-oauth-first-party-apps-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - native apps
 - first-party
 - oauth
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "aaronpk/oauth-first-party-apps"
  latest: "https://aaronpk.github.io/oauth-first-party-apps/draft-parecki-oauth-first-party-apps.html"

author:
 -
    fullname: Aaron Parecki
    organization: Okta
    email: aaron@parecki.com
 -  fullname: George Fletcher
    organization: Capital One Financial
    email: george.fletcher@capitalone.com
 -  fullname: Pieter Kasselman
    organization: Microsoft
    email: pieter.kasselman@microsoft.com

normative:
  RFC6749:
  RFC7159:
  RFC7515:
  RFC7519:
  RFC7591:
  RFC7636:
  RFC8259:
  RFC8414:
  RFC8628:
  RFC8707:
  RFC9126:
  RFC9449:
  RFC9470:
  I-D.ietf-oauth-cross-device-security:
  OpenID.Native-SSO:
    title: OpenID Connect Native SSO for Mobile Apps
    target: https://openid.net/specs/openid-connect-native-sso-1_0.html
    author:
      - ins: G. Fletcher
    date: November 2022
  OpenID:
    title: OpenID Connect Core 1.0
    target: https://openid.net/specs/openid-connect-core-1_0.html
    date: November 8, 2014
    author:
      - ins: N. Sakimura
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore
  IANA.oauth-parameters:
  IANA.JWT:
  USASCII:
    title: "Coded Character Set -- 7-bit American Standard Code for Information Interchange, ANSI X3.4"
    author:
      name: "American National Standards Institute"
    date: 1986
  SHS:
    title: "\"Secure Hash Standard (SHS)\", FIPS PUB 180-4, DOI 10.6028/NIST.FIPS.180-4"
    author:
      name: "National Institute of Standards and Technology"
    date: August 2015
    target: http://dx.doi.org/10.6028/NIST.FIPS.180-4

informative:
  RFC8252:
  I-D.ietf-oauth-browser-based-apps:

--- abstract

This document defines the Authorization Challenge Endpoint, which supports
a first-party client that wants to control the process of
obtaining authorization from the user using a native experience.

In many cases, this can provide an entirely browserless OAuth 2.0 experience suited for native
applications, only delegating to the browser in unexpected, high risk, or error conditions.


--- middle

# Introduction

This document extends the OAuth 2.0 Authorization Framework {{RFC6749}} with
a new endpoint, `authorization_challenge_endpoint`, to support first-party
applications that want to control the process of obtaining authorization from
the user using a native experience.

The client collects any initial information from the user and POSTs that information
as well as information about the client's request to the Authorization Challenge Endpoint,
and receives either an authorization code or an error code in response. The error code
may indicate that the client can continue to prompt the user for more information,
or can indicate that the client needs to launch a browser to have the user complete
the flow in a browser.

The Authorization Challenge Endpoint is used to initiate the OAuth flow in place of redirecting
or launching a browser to the authorization endpoint.

While a fully-delegated approach using the redirect-based Authorization Code grant is generally
preferred, this draft provides a mechanism for the client to directly interact
with the user. This requires a high degree of trust between the authorization server
and the client, as there typically is for first-party applications.
It should only be considered when there are usability
concerns with a redirect-based approach, such as for native mobile or desktop applications.

This draft also extends the token response (typically for use in response to a refresh token request) and resource server response to allow the authorization server or resource server to indicate that the client should re-request authorization from the user. This can include requesting step-up authentication by including parameters defined in {{RFC9470}} as well.

## Usage and Applicability

This specification MUST only be used by first-party applications, which is when the authorization server and application are operated by the same entity and the user understands them both as the same entity.

This specification MUST NOT be used by third party applications, and the authorization server SHOULD take measures to prevent use by third party applications. (e.g. only enable this grant for certain client IDs, and take measures to authenticate first-party apps when possible.)

Using this specification in scenarios other than those described will lead to unintended security and privacy problems for users and service providers.

This specification is designed to be used by first-party native applications, which includes both mobile and desktop applications.

If you provide multiple apps and expect users to use multiple apps on the same device, there may be better ways of sharing a user's login between the apps other than each app implementing this specification or using an SDK that implements this specification. For example, {{OpenID.Native-SSO}} provides a mechanism for one app to obtain new tokens by exchanging tokens from another app, without any user interaction. See {{multiple-applications}} for more details.

## Limitations of this specification

The scope of this specification is limited to first-party applications. Please review the entirety of {{security-considerations}}, and when more than one first-party application is supported, {{multiple-applications}}.

While this draft provides the framework for a native OAuth experience, each implementation
will need to define the specific behavior that it expects from OAuth clients interacting with the authorization server. While this lack of clearly defining the details would typically lead to less interoperability, it is acceptable in this case since we intend this specification to be deployed in a tightly coupled environment since it is only applicable to first-party applications.

## User Experience Considerations

It is important to consider the user experience implications of different authentication challenges as well as the device with which the user is attempting to authorize.

For example, requesting a user to enter a password on a limited-input device (e.g. TV) creates a lot of user friction while also exposing the user's password to anyone else in the room. On the other hand, using a challenge method that involves, for example, a fingerprint reader on the TV remote allowing for a FIDO2 passkey authentication would be a good experience.

The Authorization Server SHOULD consider the user's device when presenting authentication challenges and developers SHOULD consider whether the device implementing this specification can provide a good experience for the user. If the combination of user device and authentication challenge methods creates a lot of friction or security risk, consider using a specification like OAuth 2.0 Device Authorization Grant {{RFC8628}}. If selecting OAuth 2.0 Device Authorization Grant {{RFC8628}} which uses a cross-device authorization mechanism, please incorporate the security best practices identified in Cross-Device Flows: Security Best Current Practice {{I-D.ietf-oauth-cross-device-security}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Terminology

This specification uses the terms "Access Token", "Authorization Code",
"Authorization Endpoint", "Authorization Server" (AS), "Client", "Client Authentication",
"Client Identifier", "Client Secret", "Grant Type", "Protected Resource",
"Redirection URI", "Refresh Token", "Resource Owner", "Resource Server" (RS)
and "Token Endpoint" defined by {{RFC6749}}.

TODO: Replace RFC6749 references with OAuth 2.1

# Protocol Overview

There are three primary ways this specification extends various parts of an OAuth system.

## Initial Authorization Request

~~~ ascii-art
                                                +-------------------+
                                                |   Authorization   |
                          (B)Authorization      |      Server       |
             +----------+    Challenge Request  |+-----------------+|
(A)Client+---|  First-  |---------------------->||  Authorization  ||
   Starts|   |  Party   |                       ||   Challenge     ||
   Flow  +-->|  Client  |<----------------------||    Endpoint     ||
             |          | (C)Authorization      ||                 ||
             |          |    Error Response     ||                 ||
             |          |         :             ||                 ||
             |          |         :             ||                 ||
             |          | (D)Authorization      ||                 ||
             |          |    Challenge Request  ||                 ||
             |          |---------------------->||                 ||
             |          |                       ||                 ||
             |          |<----------------------||                 ||
             |          | (E) Authorization     |+-----------------+|
             |          |     Code Response     |                   |
             |          |                       |                   |
             |          |                       |                   |
             |          |                       |                   |
             |          | (F) Token             |                   |
             |          |     Request           |+-----------------+|
             |          |---------------------->||      Token      ||
             |          |                       ||     Endpoint    ||
             |          |<----------------------||                 ||
             |          | (G) Access Token      |+-----------------+|
             |          |                       |                   |
             +----------+                       +-------------------+
~~~
Figure: First-Party Client Authorization Code Request

- (A) The first-party client starts the flow, by presenting the user with a "sign in" button, or collecting information from the user, such as their email address or username.
- (B) The client initiates the authorization request by making a POST request to the Authorization Challenge Endpoint, optionally with information collected from the user (e.g. email or username)
- (C) The authorization server determines whether the information provided to the Authorization Challenge Endpoint is sufficient to grant authorization, and either responds with an authorization code or responds with an error. In this example, it determines that additional information is needed and responds with an error. The error may contain additional information to guide the Client on what information to collect next. This pattern of collecting information, submitting it to the Authorization Challenge Endpoint and then receving an error or authorization code may repeat several times.
- (D) The client gathers additional information (e.g. signed passkey challenge, or one-time code from email) and makes a POST request to the Authorization Challenge Endpoint.
- (E) The Authorization Challenge Endpoint returns an authorization code.
- (F) The client sends the authorization code received in step (E) to obtain a token from the Token Endpoint.
- (G) The Authorization Server returns an Access Token from the Token Endpoint.

## Refresh Token Request

When the client uses a refresh token to obtain a new access token, the authorization server MAY respond with an error to indicate that re-authorization of the user is required.

## Resource Request

When making a resource request to a resource server, the resource server MAY respond with an error according to OAuth 2.0 Step-Up Authentication Challenge Protocol {{RFC9470}}, indicating that re-authorization of the user is required.


# Protocol Endpoints

## Authorization Challenge Endpoint {#authorization-challenge-endpoint}

The authorization challenge endpoint is a new endpoint defined by this specification which the first-party application uses to obtain an authorization code.

The authorization challenge endpoint is an HTTP API at the authorization server that accepts HTTP POST requests with parameters in the HTTP request message body using the `application/x-www-form-urlencoded` format. This format has a character encoding of UTF-8, as described in Appendix B of {{RFC6749}}. The authorization challenge endpoint URL MUST use the "https" scheme.

If the authorization server requires client authentication for this client on the Token Endpoint, then the authorization server MUST also require client authentication for this client on the Authorization Challenge Endpoint. See {{client-authentication}} for more details.

Authorization servers supporting this specification SHOULD include the URL of their authorization challenge endpoint in their authorization server metadata document {{RFC8414}} using the `authorization_challenge_endpoint` parameter as defined in {{authorization-server-metadata}}.

The endpoint accepts the authorization request parameters defined in {{RFC6749}} for the authorization endpoint as well
as all applicable extensions defined for the authorization endpoint. Some examples of such extensions include Proof
Key for Code Exchange (PKCE) {{RFC7636}}, Resource Indicators {{RFC8707}}, and OpenID Connect {{OpenID}}. It is
important to note that some extension parameters have meaning in a web context but don't have meaning in a native
mechanism (e.g. `response_mode=query`). It is out of scope as to what the AS does in the case that an extension
defines a parameter that has no meaning in this use case.

The client initiates the authorization flow with or without information collected from the user (e.g. a signed passkey challenge or MFA code).

The authorization challenge endpoint response is either an authorization code or an error code, and may also contain an `auth_session` which the client uses on subsequent requests to the authorization challenge endpoint.


## Token endpoint

The token endpoint is used by the client to obtain an access token by
presenting its authorization grant or refresh token, as described in
Section 3.2 of OAuth 2.0 {{RFC6749}}.

This specification extends the token endpoint response to allow the authorization
server to indicate that further authentication of the user is required.


# Authorization Initiation {#authorization-initiation}

A client may wish to initiate an authorization flow by first prompting the user for their user identifier or other account information. The authorization challenge endpoint is a new endpoint to collect this login hint and direct the client with the next steps, whether that is to do an MFA flow, or perform an OAuth redirect-based flow.

In order to preserve the security of this specification, the Authorization Server MUST verify the "first-partyness" of the client before continuing with the authentication flow. Please see {{first-party-applications}} for additional considerations.

## Authorization Challenge Request {#challenge-request}

The client makes a request to the authorization challenge endpoint by adding the
following parameters, as well as parameters from any extensions, using the `application/x-www-form-urlencoded`
format with a character encoding of UTF-8 in the HTTP request body:

"client_id":
: REQUIRED if the client is not authenticating with the
  authorization server and if no `auth_session` is included.

"scope":
: OPTIONAL. The OAuth scope defined in {{RFC6749}}.

"acr_values":
: OPTIONAL. The acr_values requested by the client.

"auth_session":
: OPTIONAL. If the client has previously obtained an auth session, described in {{auth-session}}.

"code_challenge":
: OPTIONAL. The code challenge as defined by {{RFC7636}}.
  See {{redirect-to-web}} for details.

"code_challenge_method":
: OPTIONAL. The code challenge method as defined by {{RFC7636}}.
  See {{redirect-to-web}} for details.

Specific implementations as well as extensions to this specification MAY define additional parameters to be used at this endpoint.

For example, the client makes the following request to initiate a flow
given the user's phone number, line breaks shown for illustration purposes only:

    POST /authorize HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    login_hint=%2B1-310-123-4567&scope=profile
    &client_id=bb16c14c73415

## Authorization Challenge Response {#challenge-response}

The authorization server determines whether the information provided up to this point is sufficient to issue an authorization code, and if so responds with an authorization code. If the information is not sufficient for issuing an authorization code, then the authorization server MUST respond with an error response.

### Authorization Code Response

The authorization server issues an authorization code
by creating an HTTP response content using the `application/json`
media type as defined by {{RFC8259}} with the following parameters
and an HTTP 200 (OK) status code:

"authorization_code":
:   REQUIRED. The authorization code issued by the authorization server.

For example,

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "authorization_code": "uY29tL2F1dGhlbnRpY"
    }

### Error Response {#challenge-error-response}

If the request contains invalid parameters or incorrect data,
or if the authorization server wishes to interact with the user directly,
the authorization server responds with an HTTP 400 (Bad Request)
status code (unless specified otherwise below) and includes the following
parameters with the response:

"error":
:    REQUIRED.  A single ASCII {{USASCII}} error code from the following:

     "invalid_request":
     :     The request is missing a required parameter, includes an
           unsupported parameter value,
           repeats a parameter, includes multiple credentials,
           utilizes more than one mechanism for authenticating the
           client, or is otherwise malformed.

     "invalid_client":
     :     Client authentication failed (e.g., unknown client, no
           client authentication included, or unsupported
           authentication method).  The authorization server MAY
           return an HTTP 401 (Unauthorized) status code to indicate
           which HTTP authentication schemes are supported.  If the
           client attempted to authenticate via the `Authorization`
           request header field, the authorization server MUST
           respond with an HTTP 401 (Unauthorized) status code and
           include the `WWW-Authenticate` response header field
           matching the authentication scheme used by the client.

     "invalid_grant":
     :     The provided authorization grant or `auth_session` is
           invalid, expired, revoked, or is otherwise invalid.

     "unauthorized_client":
     :     The authenticated client is not authorized to use this
           authorization grant type.

     "invalid_scope":
     :     The requested scope is invalid, unknown, malformed, or
           exceeds the scope granted by the resource owner.

     "insufficient_authorization":
     :     The presented authorization is insufficient, and the authorization
           server is requesting the client take additional steps to
           complete the authorization.

     "redirect_to_web":
     :     The request is not able to be fulfilled with any further
           direct interaction with the user. Instead, the client
           should initiate a new authorization code flow so that the
           user interacts with the authorization server in a web browser.

     Values for the `error` parameter MUST NOT include characters
     outside the set %x20-21 / %x23-5B / %x5D-7E.

     The authorization server MAY extend these error codes with custom
     messages based on the requirements of the authorization server.

"error_description":
:    OPTIONAL.  Human-readable ASCII {{USASCII}} text providing
     additional information, used to assist the client developer in
     understanding the error that occurred.
     Values for the `error_description` parameter MUST NOT include
     characters outside the set %x20-21 / %x23-5B / %x5D-7E.

"error_uri":
:    OPTIONAL.  A URI identifying a human-readable web page with
     information about the error, used to provide the client
     developer with additional information about the error.
     Values for the `error_uri` parameter MUST conform to the
     URI-reference syntax and thus MUST NOT include characters
     outside the set %x21 / %x23-5B / %x5D-7E.

"auth_session":
:    OPTIONAL.  The auth session allows the authorization server to
     associate subsequent requests by this client with an ongoing
     authorization request sequence. The client MUST include
     the `auth_session` in follow-up requests to the challenge
     endpoint if it receives one along with the error response.

"request_uri":
:    OPTIONAL.  A request URI as described by {{RFC9126}} Section 2.2.

"expires_in":
:    OPTIONAL.  The lifetime of the `request_uri` in seconds, as
     described by {{RFC9126}} Section 2.2.

This specification requires the authorization server to define new
error codes that relate to the actions the client must take in order
to properly authenticate the user. These new error codes are specific
to the authorization server's implementation of this specification and are
intentionally left out of scope.

The parameters are included in the content of the HTTP response
using the `application/json` media type as defined by [RFC7159].  The
parameters are serialized into a JSON structure by adding each
parameter at the highest structure level.  Parameter names and string
values are included as JSON strings.  Numerical values are included
as JSON numbers.  The order of parameters does not matter and can
vary.

The authorization server MAY define additional parameters in the response
depending on the implmentation. The authorization server MAY also define
more specific content types for the error responses as long as the response
is JSON and conforms to `application/<AS-defined>+json`.

#### Redirect to Web Error Response {#redirect-to-web}

The authorization server may choose to interact directly with the user based on a risk
assesment, the introduction of a new authentication method not supported
in the application, or to handle an exception flow like account recovery.
To indicate this error to the client, the authorization server returns an
error response as defined above with the `redirect_to_web` error code.

In this case, the client is expected to initiate a new OAuth
Authorization Code flow with PKCE according to {{RFC6749}} and {{RFC7636}}.

If the client expects the frequency of this error response to be high,
the client MAY include a PKCE ({{RFC7636}}) `code_challenge` in the initial authorization
challenge request. This enables the authorization server to essentially treat
the authorization challenge request as a PAR {{RFC9126}} request, and
return the `request_uri` and `expires_in` as defined by {{RFC9126}} in the error response.
The client then uses the `request_uri` value to build an authorization request
as defined in {{RFC9126}} Section 4.


## Intermediate Requests

If the authorization server returns an `insufficient_authorization` error as described
above, this is an indication that there is further information the client
should request from the user, and continue to make requests to the authorization
server until the authorization request is fulfilled and an authorization code returned.

These intermediate requests are out of scope of this specification, and are expected
to be defined by the authorization server. The format of these requests is not required
to conform to the format of the initial authorization challenge requests
(e.g. the request format may be `application/json` rather than `application/x-www-form-urlencoded`).


### Auth Session {#auth-session}

The `auth_session` is a value that the authorization server issues in order to be able to associate subsequent requests from the same client. It is intended to be analagous to how a browser cookie associates multiple requests by the same browser to the authorization server.

The `auth_session` value is completely opaque to the client, and as such the authorization server MUST adequately protect the value from inspection by the client, for example by using a random string or using a JWE if the authorization server is not maintaining state on the backend.

If the client has an `auth_session`, the client MUST include it in future requests to the authorization challenge endpoint. The client MUST store the `auth_session` beyond the issuance of the authorization code to be able to use it in future requests.

Every response defined by this specification may include a new `auth_session` value. Clients MUST NOT assume that `auth_session` values are static, and MUST be prepared to update the stored `auth_session` value if one is received in a response.

To mitigate the risk of session hijacking, the 'auth_session' MUST be bound to the device, and the authorization server MUST reject an 'auth_session' if it is presented from a different device than the one it was bound to.

See {{auth-session-security}} for additional security considerations.

# Token Request {#token-request}

The client makes a request to the token endpoint using the authorization code it obtained from the authorization challenge endpoint.

This specification does not define any additional parameters beyond the token request parameters defined in  Section 4.1.3 of {{RFC6749}}. However, notably, the `redirect_uri` parameter will not be included in this request, because no `redirect_uri` parameter was included in the authorization request.

## Token Endpoint Successful Response

This specification extends the OAuth 2.0 {{RFC6749}} token response
defined in Section 5.1 with the additional parameter `auth_session`, defined in {{auth-session}}.

The response MAY include an `auth_session` parameter which the client is expected to include on a subsequent request to the authorization challenge endpoint. The `auth_session` parameter MAY also be included even if the authorization code was obtained through a traditional OAuth authorization code flow rather than the flow defined by this specification.

An example successful token response is below:

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "2YotnFZFEjr1zCsicMWpAA",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
      "auth_session": "uY29tL2F1dGhlbnRpY"
    }


## Token Endpoint Error Response

Upon any request to the token endpoint, including a request with a valid refresh token,
the authorization server can respond with an authorization challenge instead of a successful access token response.

An authorization challenge error response is a particular type of
error response as defined in Section 5.2 of OAuth 2.0 {{RFC6749}} where
the error code is set to the following value:

"error": "insufficient_authorization":
: The presented authorization is insufficient, and the authorization
  server is requesting the client take additional steps to
  complete the authorization.

Additionally, the response MAY contain an `auth_session` parameter which the client is expected to include on a subsequent request to the authorization challenge endpoint.

"auth_session":
:    OPTIONAL.  The optional auth session value allows the authorization server to
     associate subsequent requests by this client with an ongoing
     authorization request sequence. The client MUST include
     the `auth_session` in follow-up requests to the challenge
     endpoint if it receives one along with the error response.

For example:

    HTTP/1.1 403 Forbidden
    Content-Type: application/json
    Cache-Control: no-store

    {
      "error": "insufficient_authorization",
      "auth_session": "uY29tL2F1dGhlbnRpY"
    }


# Resource Server Error Response

Step-Up Authentication {{RFC9470}} defines a mechanism for resource servers to tell the client to start a new authorization request, including `acr_values` and `max_age`, and `scope` from RFC6750. Upon receiving this request, the client starts a new authorization request according to this specification, and includes the `acr_values`, `max_age` and `scope` returned in the error response.

This specification does not define any new parameters for the resource server error response beyond those defined in {{RFC9470}}.

# Authorization Server Metadata {#authorization-server-metadata}

The following authorization server metadata parameters {{RFC8414}} are introduced to signal the server's capability and policy with respect to first-party applications.

"authorization_challenge_endpoint":
: The URL of the authorization challenge endpoint at which a client can initiate
  an authorization request and eventually obtain an authorization code.


# Security Considerations {#security-considerations}

## First-Party Applications {#first-party-applications}

First-party applications are applications that the user recognizes as belonging to the same brand as the authorization server. For example, a bank publishing their own mobile application.

Because this specification enables a client application to interact directly with the end user, and the application handles sending any information collected from the user to the authorization server, it is expected to be used only for first-party applications when the authorization server also has a high degree of trust of the client.

This specification is not prescriptive on how the Authorization Server establishes its trust in the first-partyness of the application. For mobile platforms, most support some mechanism for application attestation that can be used to identify the entity that created/signed/uploaded the app to the app store. App attestation can be combined with other mechanisms like Dynamic Client Registration {{RFC7591}} to enable strong client authentication in addition to client verification (first-partyness). The exact steps required are out of scope for this specification. Note that applications running inside a browser (e.g. Single Page Apps) context it is much more difficult to verify the first-partyness of the client. Please see {{single-page-apps}} for additional details.

## Phishing {#phishing}

There are two ways using this specification increases the risk of phishing.

With this specification, the client interacts directly with the end user, collecting information provided by the user and sending it to the authorization server. If an attacker impersonates the client and successfully tricks a user into using it, they may not realize they are giving their credentials to the malicious application.

In a traditional OAuth deployment using the redirect-based authorization code flow, the user will only ever enter their credentials at the authorization server, and it is straightforward to explain to avoid entering credentials in other "fake" websites. By introducing a new place the user is expected to enter their credentials using this specification, it is more complicated to teach users how to recognize other fake login prompts that might be attempting to steal their credentials.

Because of these risks, the authorization server MAY decide to require that the user go through a redirect-based flow at any stage of the process based on its own risk assessment.


## Credential Stuffing Attacks {#credential-attacks}

The authorization challenge endpoint is capable of directly receiving user credentials and returning authorization codes. This exposes a new vector to perform credential stuffing attacks, if additional measures are not taken to ensure the authenticity of the application.

An authorization server may already have a combination of built-in or 3rd party security tools in place to monitor and reduce this risk in browser-based authentication flows. Implementors SHOULD consider similar security measures to reduce this risk in the authorization challenge endpoint. Additionally, the attestation APIs SHOULD be used when possible to assert a level of confidence to the authorization server that the request is originating from an application owned by the same party.

## Client Authentication {#client-authentication}

Typically, mobile and desktop applications are considered "public clients" in OAuth, since they cannot be shipped with a statically configured set of client credentials {{RFC8252}}. Because of this, client impersonation should be a concern of anyone deploying this pattern. Without client authentication, a malicious user or attacker can mimick the requests the application makes to the authorization server, pretending to be the legitimate client.

Because this specification is intended for first-party applications, it is likely that the intent is to also avoid prompting the user with a consent screen as recommended by {{RFC6749}}.

Implementers SHOULD consider additional measures to limit the risk of client impersonation, such as using attestation APIs available from the operating system.


## Sender Constrained Tokens
Tokens issued in response to an authorization challenge request SHOULD be sender constrained to mitigate the risk of token theft and replay.

Proof-of-Possession techniques constrain tokens by binding them to a cryptographic key. Whenever the token is presented, it MUST be accompanied by a proof that the client presenting the token also controls the cryptographic key bound to the token. If a proof-of-possession sender constrained token is presented without valid proof of possession of the cryptographic key, it MUST be rejected.

### DPoP: Demonstrating Proof-of-Possession

DPoP ({{RFC9449}}) is an application-level mechanism for sender-constraining OAuth {{RFC6749}} access and refresh tokens. If DPoP is used to sender constrain tokens, the client SHOULD use DPoP for every token request to the Authorization Server and interaction with the Resource Server.

DPoP includes an optional capability to bind the authorization code to the DPoP key to enable end-to-end binding of the entire authorization flow. Given the back-channel nature of this specification, there are far fewer opportunities for an attacker to access the authorization code and PKCE code verifier compared to the redirect-based Authorization Code Flow. In this specification, the Authorization Code is obtained via a back-channel request. Despite this, omitting Authorization Code binding leaves a gap in the end-to-end protection that DPoP provides, so DPoP Authorization Code binding SHOULD be used.

The mechanism for Authorization Code binding with DPoP is similar as that defined for Pushed Authorization Requests (PARs) in Section 10.1 of {{RFC9449}}. In order to bind the Authorization Code with DPoP, the client MUST add the DPoP header to the Authorization Challenge Request. The authorization server MUST check the DPoP proof JWT that was included in the DPoP header as defined in Section 4.3 of {{RFC9449}}. The authorization server MUST ensure that the same key is used in all subsequent Authorization Challenge Requests, or in the eventual token request. The authorization server MUST reject subsequent Authorization Challenge Requests, or the eventual token request, unless a DPoP proof for the same key presented in the original Authorization Challenge Request is provided.

The above mechanism simplifies the implementation of the client, as it can attach the DPoP header to all requests to the authorization server regardless of the type of request. This mechanism provides a stronger binding than using the `dpop_jkt` parameter, as the DPoP header contains a proof of possession of the private key.

### Other Proof of Possession Mechanisms

It may be possible to use other proof of possession mechanisms to sender constrain access and refresh tokens. Defining these mechanisms are out of scope for this specification.

## Auth Session {#auth-session-security}

### Auth Session DPoP Binding

If the client and authorization server are using DPoP binding of access tokens and/or authorization codes, then the `auth_session` value SHOULD be protected by the DPoP binding as well. The authorization server SHOULD bind the `auth_session` value to the DPoP public key. If the authorization server is binding the `auth_session` value to the DPoP public key, it MUST check that the same DPoP public key is being used and MUST verify the DPoP proof to ensure the client controls the corresponding private key whenever the client includes the `auth_session` in an Authorization Challenge Request as described in {{challenge-request}}.

DPoP binding of the `auth_session` value ensures that the context referenced by the `auth_session` cannot be stolen and reused by another device.

### Auth Session Lifetime

This specification makes no requirements or assumptions on the lifetime of the `auth_session` value. The lifetime and expiration is at the discretion of the authorization server, and the authorization server may choose to invalidate the value for any reason such as scheduled expiration, security events, or revocation events.

Clients MUST NOT make any assumptions or depend on any particular lifetime of the `auth_session` value.


## Multiple Applications {#multiple-applications}

When multiple first-party applications are supported by the AS, then it is important to consider a number of additional risks. These risks fall into two main categories: Experience Risk and Technical Risk which are described below.

### User Experience Risk

Any time a user is asked to provide the authentication credentials in user experiences that differ, it has the effect of increasing the likelihood that the user will fall prey to a phishing attack because they are used to entering credentials in different looking experiences. When multiple first-party applications are supported, the implementation MUST ensure the native experience is identical across all the first-party applications.

Another experience risk is user confusion caused by different looking experiences and behaviors. This can increase the likelihood the user will not complete the authentication experience for the first-party application.

### Technical Risk

In addition to the experience risks, multiple implementations in first-party applications increases the risk of an incorrect implementation as well as increasing the attack surface as each implementation may expose its own weaknesses.

### Mitigation

To address these risks, when multiple first-party applications must be supported, and other methods such as {{OpenID.Native-SSO}} are not applicable, it is RECOMMENDED that a client-side SDK be used to ensure the implementation is consistent across the different applications and to ensure the user experience is identical for all first-party apps.

## Single Page Applications {#single-page-apps}

Single Page Applications (SPA) run in a scripting language inside the context of a browser instance. This environment poses several unique challenges compared to native applications, in particular:

* Significant attack vectors due to the possibility of Cross-Site Scripting (XSS) attacks
* Fewer options to securely attest to the first-partyness of a browser based application

See {{I-D.ietf-oauth-browser-based-apps}} for a detailed discussion of the risks of XSS attacks in browsers.

Additionally, the nature of a Single-Page App means the user is already in a browser context, so the user experience cost of doing a full page redirect or a popup window for the traditional OAuth Authorization Code Flow is much less than the cost of doing so in a native application. The complexity and risk of implementing this specification in a browser likely does not outweigh the user experience benefits that would be gained in that context.

For these reasons, it is NOT RECOMMENDED to use this specification in browser-based applications.


# IANA Considerations

## OAuth Parameters Registration

IANA has (TBD) registered the following values in the IANA "OAuth Parameters" registry of {{IANA.oauth-parameters}} established by {{RFC6749}}.

**Parameter name**: `auth_session`

**Parameter usage location**: token response

**Change Controller**: IETF

**Specification Document**: Section 5.4 of this specification

## OAuth Server Metadata Registration

IANA has (TBD) registered the following values in the IANA "OAuth Authorization Server Metadata" registry of {{IANA.oauth-parameters}} established by {{RFC8414}}.

**Metadata Name**: `authorization_challenge_endpoint`

**Metadata Description**: URL of the authorization server's authorization challenge endpoint.

**Change Controller**: IESG

**Specification Document**: Section 4.1 of [[ this specification ]]

--- back

# Example User Experiences

This section provides non-normative examples of how this specification may be used to support specific use cases.

## Passkey

A user may log in with a passkey (without a password).

* The Client collects the username from the user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username.
* The Authorization Server verifies the username and returns a challenge
* The Client signs the challenge using the platform authenticator, which results in the user being prompted for verification with biometrics or a PIN.
* The Client sends the signed challenge, username, and credential ID to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server verifies the signed challenge and returns an Authorization Code.
* The Client requests an Access Token and Refresh Token by issuing a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.

## Redirect to Authorization Server

A user may be redirected to the Authorization Server to perfrom an account reset.

* The Client collects username from the user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username.
* The Authorization Server verifies the username and determines that the account is locked and returns a Redirect error response.
* The Client parses the redirect message, opens a browser and redirects the user to the Authorization Server performing an OAuth 2.0 flow with PKCE.
* The user resets their account by performing a multi-step authentication flow with the Authorization Server.
* The Authorization Server issues an Authorization Code in a redirect back to the client, which then exchanges it for an access and refresh token.


## Passwordless One-Time Password (OTP)

In a passwordless One-Time Password (OTP) scheme, the user is in possession of a one-time password generator. This generator may be a hardware device, or implemented as an app on a mobile phone. The user provides a user identifier and one-time password, which is verified by the Authorization Server before it issues an Authorization Code, which can be exchanged for an Access and Refresh Token.

* The Client collects username and OTP from user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username and OTP.
* The Authorization Server verifies the username and OTP and returns an Authorization Code.
* The Client requests an Access Token and Refresh Token by issuing a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.

## E-Mail Confirmation Code

A user may be required to provide an e-mail confirmation code as part of an authentication ceremony to prove they control an e-mail address. The user provides an e-mail address and is then required to enter a verification code sent to the e-mail address. If the correct verification code is returned to the Authorization Server, it issues Access and Refresh Tokens.

* The Client collects an e-mail address from the user.
* The Client sends the e-mail address in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server sends a verification code to the e-mail address and returns an Error Response ({{challenge-error-response}}) including `"error": "insufficient_authorization"`, `"auth_session"` and a custom property indicating that an e-mail verification code must be entered.
* The Client presents a user experience guiding the user to copy the e-mail verification code to the Client. Once the e-mail verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the e-mail verification code as well as the `auth_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `auth_session` to maintain the session and verifies the e-mail verification code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the Access Token and Refresh Token.

## SMS Confirmation Code
A user may be required to provide an SMS confirmation code as part of an authentication ceremony to prove they control a mobile phone number. The user provides a phone number and is then required to enter an SMS confirmation code sent to the phone. If the correct confirmation code is returned to the Authorization Server, it issues Access and Refresh Tokens.

* The Client collects a mobile phone number from the user.
* The Client sends the phone number in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server sends a confirmation code to the phone number and returns an Error Response ({{challenge-error-response}}) including `"error": "insufficient_authorization"`, `"auth_session"` and a custom property indicating that a SMS confirmation code must be entered.
* The Client presents a user experience guiding the user to enter the SMS confirmation code. Once the SMS verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the confirmation code as well as the `auth_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `auth_session` to maintain the session context and verifies the SMS code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the Access Token and Refresh Token.

## Re-authenticating to an app a week later using OTP
A client may be in possession of an Access and Refresh Token as the result of a previous succesful user authentication. The user returns to the app a week later and accesses the app. The Client presents the Access Token, but receives an error indicating the Access Token is no longer valid. The Client presents a Refresh Token to the Authorization Server to obtain a new Access Token. If the Authorization Server requires user interaction for reasons based on its own policies, it rejects the Refresh Token and the Client re-starts the user authentication flow to obtain new Access and Refresh Tokens.

* The Client has a short-lived access token and long-lived refresh token following a previous completion of an Authorization Grant Flow which included user authentication.
* A week later, the user launches the app and tries to access a protected resource at the Resource Server.
* The Resource Server responds with an error code indicating an invalid access token since it has expired.
* The Client presents the refresh token to the Authorization Server to obtain a new access token (section 6 {{RFC6749}})
* The Authorization Server responds with an error code indicating that an OTP from the user is required, as well as an `auth_session`.
* The Client prompts the user to enter an OTP.
* The Client sends the OTP and `auth_session` in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server verifies the `auth_session` and OTP, and returns an Authorization Code.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.
* The Client presents the new Access Token to the Resource Server in order to access the protected resource.

## Step-up Authentication using Confirmation SMS
A Client previously obtained an Access and Refresh Token after the user authenticated with an OTP. When the user attempts to access a protected resource, the Resource Server determines that it needs an additional level of authentication and triggers a step-up authentication, indicating the desired level of authentication using `acr_values` and `max_age` as defined in the Step-up Authentication specification. The Client initiates an authorization request with the Authorization Server indicating the `acr_values` and `max_age` parameters. The Authorization Server responds with error messages promptng for additional authentication until the `acr_values` and `max_age` values are satisfied before issuing fresh Access and Refresh Tokens.

* The Client has a short-lived access token and long-lived refresh token following the completion of an Authorization Code Grant Flow which included user authentication.
* When the Client presents the Access token to the Resource Server, the Resource Server determines that the `acr` claim in the Access Token is insufficient given the resource the user wants to access and responds with an `insufficient_user_authentication` error code, along with the desired `acr_values` and desired `max_age`.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the `auth_session`, `acr_values` and `max_age` parameters.
* The Authorization Server verifies the `auth_session` and determines which authentication methods must be satisfied based on the `acr_values`, and responds with an Error Response ({{challenge-error-response}}) including `"error": "insufficient_authorization"` and a custom property indicating that an OTP must be entered.
* The Client prompts the user for an OTP, which the user obtains and enters.
* The Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint including the `auth_session` and OTP.
* The Authorization Server verifies the OTP and returns an Authorization Code.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues an Access Token with the updated `acr` value along with the Refresh Token.
* The Client presents the Access Token to the Resources Server, which verifies that the `acr` value meets its requirements before granting access to the protected resource.

## Registration
This example describes how to use the mechanisms defined in this draft to create a complete user registration flow starting with an email address. In this example, it is the Authorization Server's policy to allow these challenges to be sent to email and phone number that were previously unrecognized, and creating the user account on the fly.

* The Client collects a username from the user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username.
* The Authorization Server returns an Error Response ({{challenge-error-response}}) including `"error": "insufficient_authorization"`, `"auth_session"`, and a custom property indicating that an e-mail address must be collected.
* The Client collects an e-mail address from the user.
* The Client sends the e-mail address as part of a second Authorization Challenge Request to the Authorization Challenge Endpoint, along with the `auth_session` parameter.
* The Authorization Server sends a verification code to the e-mail address and returns an Error Response including `"error": "insufficient_authorization"`, `"auth_session"` and a custom property indicating that an e-mail verification code must be entered.
* The Client presents a user experience guiding the user to copy the e-mail verification code to the Client. Once the e-mail verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the e-mail verification code as well as the `auth_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `auth_session` to maintain the session context, and verifies the e-mail verification code. It determines that it also needs a phone number for account recovery purposes and returns an Error Response including `"error": "insufficient_authorization"`, `"auth_session"` and a custom property indicating that a phone number must be collected.
* The Client collects a mobile phone number from the user.
* The Client sends the phone number in an Authorization Challenge Request to the Authorization Challenge Endpoint, along with the `auth_session`.
* The Authorization Server uses the `auth_session` parameter to link the previous requests. It sends a confirmation code to the phone number and returns an Error Response including `"error": "insufficient_authorization"`, `"auth_session"` and a custom property indicating that a SMS confirmation code must be entered.
* The Client presents a user experience guiding the user to enter the SMS confirmation code. Once the SMS verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the confirmation code as well as the `auth_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `auth_session` to maintain the session context, and verifies the SMS verification code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.

# Example Implementations

In order to successfully implement this specification, the Authorization Server will need to define its own specific requirements for what values clients are expected to send in the Authorization Challenge Request ({{challenge-request}}), as well as its own specific error codes in the Authorization Challenge Response ({{challenge-response}}).

Below is an example of parameters required for a complete implementation that enables the user to log in with a username and OTP.

## Authorization Challenge Request Parameters

In addition to the request parameters defined in {{challenge-request}}, the authorization server defines the additional parameters below.

"username":
: REQUIRED for the initial Authorization Challenge Request.

"otp":
: The OTP collected from the user. REQUIRED when re-trying an Authorization Challenge Request in response to the `otp_required` error defined below.


## Authorization Challenge Response Parameters

In addition to the response parameters defined in {{challenge-response}}, the authorization server defines the additional value for the `error` response below.

"otp_required":
:     The client should collect an OTP from the user and send the OTP in
      a second request to the Authorization Challenge Endpoint. The HTTP
      response code to use with this error value is `401 Unauthorized`.

## Example Sequence

The client prompts the user to enter their username, and sends the username in an initial Authorization Challenge Request.

    POST /authorize HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    username=alice
    &scope=photos
    &client_id=bb16c14c73415

The Authorization Server sends an error response indicating that an OTP is required.

    HTTP/1.1 401 Unauthorized
    Content-Type: application/json
    Cache-Control: no-store

    {
      "error": "otp_required",
      "auth_session": "ce6772f5e07bc8361572f"
    }

The client prompts the user for an OTP, and sends a new Authorization Challenge Request.

    POST /authorize HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    auth_session=ce6772f5e07bc8361572f
    &otp=555121

The Authorization Server validates the `auth_session` to find the expected user, then validates the OTP for that user, and responds with an authorization code.


    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "authorization_code": "uY29tL2F1dGhlbnRpY"
    }

The client sends the authorization code to the token endpoint.

    POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code
    &client_id=bb16c14c73415
    &code=uY29tL2F1dGhlbnRpY

The Authorization Server responds with an access token and refresh token.

    HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "token_type": "Bearer",
      "expires_in": 3600,
      "access_token": "d41c0692f1187fd9b326c63d",
      "refresh_token": "e090366ac1c448b8aed84cbc07"
    }

# Design Goals

Rather than extend the OAuth token endpoint with additional grant types, this specification defines a new authorization flow the client can use to obtain an authorization flow. There are two primary reasons for designing the specification this way.

This enables existing OAuth implementations to make fewer modifications to existing code by not needing to extend the token endpoint with new logic. Instead, the new logic can be encapsulated in an entirely new endpoint, the output of which is an authorization code which can be redeemed for an access token at the existing token endpoint.

This also mirrors more closely the existing architecture of the redirect-based authorization code flow. In the authorization code flow, the client first initiates a request by redirecting a browser to the authorization endpoint, at which point the authorization server takes over with its own custom logic to authenticate the user in whatever way appropriate. Afterwards, the authorization server redirects the user back to the client application with an authorization code in the query string. This specification mirrors the existing approach by having the client first make a POST request to the "authorization challenge endpoint", at which point the authorization server provides its own custom logic to authenticate the user, eventually returning an authorization code.

These design decisions should enable authorization server implementations to isolate and encapsulate the changes needed to support this specification.


# Document History

-02

* Fixed typos

-01

* Added clarification on use of authorization code binding when using DPoP with the authorization challenge endpoint.
* Removed ash claim to simplify DPoP binding with auth_session value.
* Fixed how "redirect to web" mechanism works with PKCE.
* Added "intermediate requests" section to clarify these requests are out of scope, moved "auth session" description to that section.

-00

* Renamed `authorization_required` to `insufficient_authorization`
* Defined `insufficient_authorization` on the Authorization Challenge Endpoint
* Renamed `device_session` to `auth_session`
* Added explicit method to indicate the client should restart the flow in a browser
* Described how to use DPoP in conjunction with this spec


# Acknowledgments
{:numbered="false"}

The authors would like to thank the attendees of the OAuth Security Workshop 2023 session in which this was discussed, as well as the following individuals who contributed ideas, feedback, and wording that shaped and formed the final specification:

Brian Campbell, Dick Hardt, Dmitry Telegin, John Bradley, Justin Richer, Mike Jones, Orie Steele, Tobias Looker, Yaron Sheffer.


