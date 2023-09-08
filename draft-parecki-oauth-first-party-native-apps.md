---
title: "OAuth 2.0 for First-Party Native Applications"
abbrev: "OAuth for First-Party Native Apps"
category: std

docname: draft-parecki-oauth-first-party-native-apps-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - native apps
 - oauth
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "aaronpk/oauth-first-party-native-apps"
  latest: "https://aaronpk.github.io/oauth-first-party-native-apps/draft-parecki-oauth-first-party-native-apps.html"

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
  RFC7636:
  RFC8259:
  RFC8414:
  RFC8707:
  I-D.ietf-oauth-step-up-authn-challenge:
  I-D.ietf-oauth-dpop:
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
  IANA.OAuth.Parameters:
  USASCII:
    title: "Coded Character Set -- 7-bit American Standard Code for Information Interchange, ANSI X3.4"
    author:
      name: "American National Standards Institute"
    date: 1986

informative:
  RFC8252:

--- abstract

This document defines the Authorization Challenge Endpoint, which supports
a first-party native client that wants to control the process of
obtaining authorization from the user using a native experience.

In many cases, this can provide an entirely browserless OAuth 2.0 experience suited for native
applications, only delegating to the browser in unexpected, high risk, or error conditions.


--- middle

# Introduction

This document extends the OAuth 2.0 Authorization Framework {{RFC6749}} with
a new endpoint, `authorization_challenge_endpoint`, to support first-party native
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

This draft also extends the token response (typically for use in response to a refresh token request) and resource server response to allow the authorization server or resource server to indicate that the client should re-request authorization from the user. This can include requesting step-up authentication by including parameters defined in {{I-D.ietf-oauth-step-up-authn-challenge}} as well.

## Usage and Applicability

This specification MUST only be used by first-party applications, which is when the authorization server and application are operated by the same entity and the user understands them both as the same entity.

This specification MUST NOT be used by third party applications, and the authorization server SHOULD take measures to prevent use by third party applications. (e.g. only enable this grant for certain client IDs, and take measures to authenticate first-party apps when possible.)

Using this specification in scenarios other than those described will lead to unintended security and privacy problems for users and service providers.

This specification is designed to be used by native applications, which includes both mobile and desktop applications.

If you provide multiple apps and expect users to use multiple apps on the same device, there may be better ways of sharing a user's login between the apps other than each app implementing this specification or using an SDK that implements this specification. For example, {{OpenID.Native-SSO}} provides a mechanism for one app to obtain new tokens by exchanging tokens from another app, without any user interaction. See {{multiple-applications}} for more details.

## Limitations of this specification

The scope of this specification is limited to first-party native applications. Please review the entirety of {{security-considerations}}, and when more than one first-party native application is supported, {{multiple-applications}}.

While this draft provides the framework for a native OAuth experience, each implementation
will need to define the specific behavior that it expects from OAuth clients interacting with the authorization server. While this lack of clearly defining the details would typically lead to less interoperability, it is acceptable in this case since we intend this specification to be deployed in a tightly coupled environment since it is only applicable to first-party applications.

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
(A)Client+---|  Native  |---------------------->||  Authorization  ||
   Starts|   |  Client  |                       ||   Challenge     ||
   Flow  +-->|          |<----------------------||    Endpoint     ||
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
Figure: Native Client Authorization Code Request

- (A) The native client starts the flow, by presenting the user with a "sign in" button, or collecting information from the user, such as their email address or username.
- (B) The client initiates the authorization request by making a POST request to the Authorization Challenge Endpoint, optionally with information collected from the user (e.g. email or username)
- (C) The authorization server determines whether the information provided to the Authorization Challenge Endpoint is sufficient to grant authorization, and either responds with an authorization code or responds with an error. In this example, it determines that additional information is needed and responds with an error. The error may contain additional information to guide the Client on what information to collect next. This pattern of collecting information, submitting it to the Authorization Challenge Endpoint and then receing an error or authorization code may repeat several times.
- (D) The client gathers additional information (e.g. passkey, or one-time code from email) and makes a POST request to the Authorization Challenge Endpoint.
- (E) The Authorization Challenge Endpoint returns an authorization code.
- (F) The native client sends the authorization code received in step (E) to obtain a token from the Token Endpoint.
- (G) The Authorization Server returns an Access Token from the Token Endpoint.

## Refresh Token Request

When the client uses a refresh token to obtain a new access token, the authorization server MAY respond with an error to indicate that re-authorization of the user is required.

## Resource Request

When making a resource request to a resource server, the resource server MAY respond with an error according to OAuth 2.0 Step-Up Authentication Challenge Protocol {{I-D.ietf-oauth-step-up-authn-challenge}}, indicating that re-authorization of the user is required.


# Protocol Endpoints

## Authorization Challenge Endpoint {#authorization-challenge-endpoint}

The authorization challenge endpoint is a new endpoint defined by this specification which the native application uses to obtain an authorization code.

The authorization challenge endpoint is an HTTP API at the authorization server that accepts HTTP POST requests with parameters in the HTTP request message body using the `application/x-www-form-urlencoded` format. This format has a character encoding of UTF-8, as described in Appendix B of {{RFC6749}}. The authorization challenge endpoint URL MUST use the "https" scheme.

Authorization servers supporting this specification SHOULD include the URL of their authorization challenge endpoint in their authorization server metadata document {{RFC8414}} using the `authorization_challenge_endpoint` parameter as defined in {{authorization-server-metadata}}.

The endpoint accepts the authorization request parameters defined in {{RFC6749}} for the authorization endpoint as well
as all applicable extensions defined for the authorization endpoint. Some examples of such extensions include Proof
Key for Code Exchange (PKCE) {{RFC7636}}, Resource Indicators {{RFC8707}}, and OpenID Connect {{OpenID}}. It is
important to note that some extension parameters have meaning in a web context but don't have meaning in a native
mechanism (e.g. `response_mode=query`). It is out of scope as to what the AS does in the case that an extension
defines a parameter that is has no meaning in this use case.

The client initiates the authorization flow with or without information collected from the user (e.g. a passkey or MFA code).

The authorization challenge endpoint response is either an authorization code or an error code, and may also contain a `device_session` which the client uses on subsequent requests to the authorization challenge endpoint.


## Token endpoint

The token endpoint is used by the client to obtain an access token by
presenting its authorization grant or refresh token, as described in
Section 3.2 of OAuth 2.0 {{RFC6749}}.

This specification extends the token endpoint response to allow the authorization
server to indicate that further authentication of the user is required.


# Authorization Initiation {#authorization-initiation}

A client may wish to initiate an authorization flow by first prompting the user for their user identifier or other account information. The authorization challenge endpoint is a new endpoint to collect this login hint and direct the client with the next steps, whether that is to do an MFA flow, or perform an OAuth redirect-based flow.

## Authorization Challenge Request {#challenge-request}

The client makes a request to the authorization challenge endpoint by adding the
following parameters, as well as parameters from any extensions, using the `application/x-www-form-urlencoded`
format with a character encoding of UTF-8 in the HTTP request body:

"client_id":
: REQUIRED if the client is not authenticating with the
  authorization server and if no `device_session` is included.

"scope":
: OPTIONAL. The OAuth scope defined in {{RFC6749}}.

"acr_values":
: OPTIONAL. The acr_values requested by the client.

"device_session":
: OPTIONAL. If the client has previously obtained a device session, described in {{device-session}}.

Specific implementations as well as extensions to this specification MAY define additional parameters to be used at this endpoint.

For example, the client makes the following request to initiate a flow
given the user's phone number, line breaks shown for illustration purposes only:

    POST /authorize HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    login_hint=%2B1-310-123-4567&scope=profile
    &client_id=bb16c14c73415

## Authorization Challenge Response {#challenge-response}

The authorization server determines whether the information provided up to this point is sufficient to issue an authorization code, and responds with an authorization code or an error message.

### Authorization Code Response

The authorization server issues an authorization code
by creating an HTTP response content using the `application/json`
media type as defined by {{RFC8259}} with the following parameters
and an HTTP 200 (OK) status code:

"authorization_code":
:   REQUIRED. The authorization code issued by the authorization server.

For example,

    HTTP/1.1 200 OK
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store

    {
      "authorization_code": "uY29tL2F1dGhlbnRpY"
    }


### Error Response {#challenge-error-response}

If the request contains invalid parameters or incorrect data,
the authorization server responds with an HTTP 400 (Bad Request)
status code (unless specified otherwise) and includes the following
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

     "unauthorized_client":
     :     The authenticated client is not authorized to use this
           authorization grant type.

     "invalid_scope":
     :     The requested scope is invalid, unknown, malformed, or
           exceeds the scope granted by the resource owner.

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

"device_session":
:    OPTIONAL.  The device session allows the authorization server to
     associate subsequent requests by this client with an ongoing
     authorization request sequence. The client MUST include
     the `device_session` in follow-up requests to the challenge
     endpoint if it receives one along with the error response.

The parameters are included in the content of the HTTP response
using the `application/json` media type as defined by [RFC7159].  The
parameters are serialized into a JSON structure by adding each
parameter at the highest structure level.  Parameter names and string
values are included as JSON strings.  Numerical values are included
as JSON numbers.  The order of parameters does not matter and can
vary.

The authorization server MAY define additional parameters in the response
depending on the implmentation.

## Device Session

The device session is completely opaque to the client, and as such the AS MUST adequately protect the value from inspection by the client, for example by using a JWE if the AS is not maintaining state on the backend.

The client MUST include the device session in future requests to the authorization challenge endpoint for the particular authorization request.

# Token Request {#token-request}

The client makes a request to the token endpoint using the authorization code it obtained from the authorization challenge endpoint.

This specification does not define any additional parameters beyond the token request parameters defined in  Section 4.1.3 of {{RFC6749}}. However, notably the `redirect_uri` parameter will not be included in this request, because no `redirect_uri` parameter was included in the authorization request.

## Token Endpoint Error Response

Upon any request to the token endpoint, including a request with a valid refresh token,
the authorization server can respond with an authorization challenge instead of a successful access token response.

An authorization challenge error response is a particular type of
error response as defined in Section 5.2 of OAuth 2.0 {{RFC6749}} where
the error code is set to the following value:

"error": "authorization_required":
: The authorization grant is insufficiently authorized, but another
  access token request may succeed if an additional authorization
  grant is presented.

"device_session":
:    OPTIONAL.  The optional device session value allows the authorization server to
     associate subsequent requests by this client with an ongoing
     authorization request sequence. The client MUST include
     the `device_session` in follow-up requests to the challenge
     endpoint if it receives one along with the error response.

For example:

    HTTP/1.1 403 Forbidden
    Content-Type: application/json;charset=UTF-8
    Cache-Control: no-store

    {
      "error": "authorization_required",
      "device_session": "uY29tL2F1dGhlbnRpY"
    }


# Resource Server Error Response

Step-Up Authentication {{I-D.ietf-oauth-step-up-authn-challenge}} defines a mechanism for resource servers to tell the client to start a new authorization request, including `acr_values` and `max_age`, and `scope` from RFC6750. Upon receiving this request, the client starts a new authorization request according to this specification, and includes the `acr_values`, `max_age` and `scope` returned in the error response.

This specification does not define any new parameters for the resource server error response beyond those defined in {{I-D.ietf-oauth-step-up-authn-challenge}}.

# Authorization Server Metadata {#authorization-server-metadata}

The following authorization server metadata parameters {{RFC8414}} are introduced to signal the server's capability and policy with respect to 1st Party Native Applications.

"authorization_challenge_endpoint":
: The URL of the authorization challenge endpoint at which a client can initiate
  an authorization request and eventually obtain an authorization code.


# Security Considerations {#security-considerations}

## First-Party Applications

Because this specification enables a client application to interact directly with the end user, and the application handles sending any information collected from the user to the authorization server, it is expected to be used only for first-party applications when the authorization server also has a high degree of trust of the client.

First-party applications are applications that the user recognizes as belonging to the same brand as the authorization server. For example, a bank publishing their own mobile application.

## Phishing {#phishing}

There are two ways using this specification increases the risk of phishing.

With this specification, the client interacts directly with the end user, collecting information provided by the user and sending it to the authorization server. If an attacker impersonates the client and successfully tricks a user into using it, they may not realize they are giving their credentials to the malicious application.

In a traditional OAuth deployment using the redirect-based authorization code flow, the user will only ever enter their credentials at the authorization server, and it is straightforward to explain to avoid entering credentials in other "fake" websites. By introducing a new place the user is expected to enter their credentials using this specification, it is more complicated to teach users how to recognize other fake login prompts that might be attempting to steal their credentials.

Because of these risks, the authorization server MAY decide to require that the user go through a redirect-based flow at any stage of the process based on its own risk assessment.


## Credential Stuffing Attacks {#credential-attacks}

The authorization challenge endpoint is capable of directly receiving user credentials and returning authorization codes. This exposes a new vector to perform credential attacks. 

An authorization server may already have a combination of built-in or 3rd party security tools in place to monitor and reduce this risk in browser-based authentication flows. Implementors SHOULD consider similar security measures to reduce this risk in the authorization challenge endpoint. Additionally, the attestation APIs SHOULD be used when possible to assert a level of confidence to the authorization server that the request is originating from an application owned by the same party.

## Client Authentication

Typically, mobile and desktop applications are considered "public clients" in OAuth, since they cannot be shipped with a statically configured set of client credentials {{RFC8252}}. Because of this, client impersonation should be a concern of anyone deploying this pattern. Without client authentication, a malicious user or attacker can mimick the requests the application makes to the authorization server, pretending to be the legitimate client.

Because this specification is intended for first-party applications, it is likely that the intent is to also avoid prompting the user with a consent screen as recommended by {{RFC6749}}.

Implementers SHOULD consider additional measures to limit the risk of client impersonation, such as using attestation APIs available from the operating system.


## Sender Constrained Tokens
Tokens issued to native apps SHOULD be sender constrained to mitigate the risk of token theft and replay.

Proof-of-Possession techniques constrain tokens by binding them to a cryptographic key. Whenever the token is presented, it should be accompanied by a proof that the client presenting the token also controls the cryptographic key bound to the token. If a proof-of-possession sender constrained token is presented without valid proof of possession of the cryptographic key, it MUST be rejected.

### Demonstrating Proof-of-Possession
DPoP is an application-level mechanism for sender-constraining OAuth {{RFC6749}} access and refresh tokens {{I-D.ietf-oauth-dpop}}. If DPoP is used to sender constrain tokens, the native client SHOULD use DPoP for every token request to the authorization Server and interaction with the Resource Server.

DPoP includes an optional capability to bind the authorization code to the DPoP key to enable end-to-end binding of the entire authorization flow. If an attacker can access the Authorization Code and PKCE code verifier as described in Section 11.9 of {{I-D.ietf-oauth-dpop}}, Authorization Code binding SHOULD be used.

To bind the authorization code using the Authorization Challenge Endpoint, the JWK Thumbprint of the DPoP key MUST be communicated to the Authorization Server by including the `dpop_jkt` parameter defined in section 10 of {{I-D.ietf-oauth-dpop}} alongside other authorization request parameters in the POST body of the first Authorization Challenge Request. If it is included in subsequent Authorization Challenge Requests, the value of this parameter must be the same as in the initial request. If the JWK Thumbprint in the `dpop_jkt` differ at any point, the Authorization Server MUST reject the request. If the `dpop_jkt` parameter is not included in the first request, but added in subsequent requests, the Authorization Server MUST reject the request (do we need to define a specific error code for that?).

### Other Proof of Possession Mechanisms
It may be possible to use other proof of possession mechanisms to sender constrain access and refresh tokens. Defining these mechanisms are out of scope for this specification.

### Device Session
* PoP binding of device session parameter

## Multiple Applications {#multiple-applications}

When there is more than one 1st-party native applications supported by the AS, then it is important to consider a number of additional risks. These risks fall into two main categories: Experience Risk and Technical Risk which are described below.

### Experience Risk
Any time a user is asked to provide the authentication credentials in user experiences that differ, it has the effect of increasing the likelihood that the user will fall prey to a phishing attack because they are used to entering credentials in different looking experiences. When multiple native applications are supported, the implementation MUST ensure the native experience is identical across all the 1st party native applications.

Another experience risk is user confusion caused by different looking experiences and behaviors. This can increase the likelihood the user will not complete the authentication experience for the 1st party native application.

### Technical Risk
In addition to the experience risks, multiple implementations in 1st party native applications increases the risk of an incorrect implementation as well as increasing the attack surface as each implementation may expose it's own weaknesses.

### Mitigation
To address these risk, when multiple 1st party native applications must be supported, and other methods such as {{OpenID.Native-SSO}} are not applicable, it is RECOMMENDED that a client-side SDK be used to ensure the implementation is consistent across the different native apps and to ensure the user experience is identical for all 1st party apps.



# IANA Considerations

IANA has (TBD) registered the following values in the IANA "OAuth Authorization Server Metadata" registry of {{IANA.OAuth.Parameters}} established by {{RFC8414}}.

**Metadata Name**: authorization_challenge_endpoint

**Metadata Description**: URL of the authorization server's authorization challenge endpoint.

**Change Controller**: IESG

**Specification Document**: Section 4.1 of [[ this specification ]]



--- back

# Example User Experiences

This section provides non-normative examples of how this specification may be used to support specific use cases.

## Passwordless One-Time Passwork (OTP)

In a passwordless One-Time Password (OTP) scheme, the user is in possession of a one-time password generator. This generator may be a hardware device, or implemented as an app on a mobile phone. The user provides a user identifier and one-time password, which is verified by the Authorization Server before it issues an Authorization Code, which can be exchanged for an Access and Refresh Token.

* The Client collects username and OTP from user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username and OTP.
* The Authorization Server verifies the username and OTP and returns an Authorization Code.
* The Client requests an Access Token and Refresh Token by issuing a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.

## E-Mail Confirmation Code

A user may be required to provide an e-mail confirmation code as part of an authentication ceremony to prove they control an e-mail address. The user provides an e-mail address and is then requried to enter a verification code sent to the e-mail address. If the correct verification code is returned to the Authorization Server, it issues Access and Refresh Tokens.

* The Client collects an e-mail address from the user.
* The Client sends the e-mail address in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server sends a verification code to the e-mail address and returns an Error Response ({{challenge-error-response}}) including `"error": "authorization_required"`, `"device_session"` and a custom error code indicating that an e-mail verification code must be entered.
* The Client presents a user experience guiding the user to copy the e-mail verification code to the Client. Once the e-mail verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the e-mail verification code as well as the `device_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `device_session` to maintain the session and verifies the e-mail verification code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the Access Token and Refresh Token.

## SMS Confirmation Code
A user may be required to provide an SMS confirmation code as part of an authentication ceremony to prove they control a mobile phone number. The user provides a phone number and is then requried to enter a SMS confirmation code sent to the phone. If the correct confirmation code is returned to the Authorization Server, it issues Access and Refresh Tokens.

* The Client collects a mobile phone number from the user.
* The Client sends the phone number in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server sends a confirmation code to the phone number and returns an Error Response ({{challenge-error-response}}) including `"error": "authorization_required"`, `"device_session"` and a custom error code indicating that a SMS confirmation code must be entered.
* The Client presents a user experience guiding the user to enter the SMS confirmation code. Once the SMS verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the confirmation code as well as the `device_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `device_session` to maintain the session context and verifies the SMS code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the Access Token and Refresh Token.

## Re-authenticating to an app a week later using OTP
A client may be in possession of an Access and Refresh Token as the result of a previous succesful user authentication. The user returns to the app a week later and accesses the app. The Client presents the Access Token, but receives an error indicating the Access Token is no longer valid. The Client presents a Refresh Token to the Authorization Server to obtain a new Access Token. If the Authorization Server requires user interaction for reasons based on its own policies, it rejects the Refresh Token and the Client re-starts the user authentication flow to obtain new Access and Refresh Tokens.

* The Client has a short-lived access token and long-lived refresh token following a previous completion of an Authorization Grant Flow which included user authentication.
* A week later, the user launches the app and tries to access a protected resource at the Resource Server.
* The Resource Server responds with an error code indicating an invalid access token since it has expired.
* The Client presents the refresh token to the Authorization Server to obtain a new access token (section 6 {{RFC6749}})
* The Authorization Server responds with an error code indicating that an OTP from the user is required, as well as a `device_session`.
* The Client prompts the user to enter an OTP.
* The Client sends the OTP and `device_session` in an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}).
* The Authorization Server verifies the `device_session` and OTP, and returns an Authorization Code.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.
* The Client presents the new Access Token to the Resource Server in order to access the protected resource.

## Step-up Authentication using Confirmation SMS
A Client previously obtained an Access and Refresh Token after the user authenticated with an OTP. When the user attempts to access a protected resource, the Resource Server determines that it needs an additional level of authentication and triggers a step-up authentication, indicating the desired level of authentication using `acr_values` and `max_age` as defined in the Step-up Authentication specification. The Client initiates an authorization request with the Authorization Server indicating the `acr_values` and `max_age` parameters. The Authorization Server responds with error messages promptng for additional authentication until the `acr_values` and `max_age` values are satisfied before issuing fresh Access and Refresh Tokens.

* The Client has a short-lived access token and long-lived refresh token following the completion of an Authorization Grant Flow which included user authentication.
* When the Client presents the Access token to the Resource Server, the Resource Server determines that the `acr` claim in the Access Token is insufficient given the resource the user wants to access and responds with an `insufficient_user_authentication` error code, along with the desired `acr_values` and desired `max_age`.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the `device_session`, `acr_values` and `max_age` parameters.
* The Authorization Server verifies the `device_session` and determines which authentication methods must be satisfied based on the `acr_values`, and responds with an Error Response ({{challenge-error-response}}) including `"error": "authorization_required"` and a custom error code indicating that an OTP must be entered.
* The Client prompts the user for an OTP, which the user obtains and enters.
* The Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint including the `device_session` and OTP.
* The Authorization Server verifies the OTP and returns an Authorization Code.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues an Access Token with the updated `acr` value along with the Refresh Token.
* The Client presents the Access Token to the Resources Server, which verifies that the `acr` value meets its requirements before granting access to the prtoected resource.

## Registration
This example describes how to use the mechanisms defined in this draft to create a complete user registration flow starting with an email address. In this example, it is the Authorization Server's policy to allow these challenges to be sent to email and phone number that were previously unrecognized, and creating the user account on the fly.

* The Client collects a username from the user.
* The Client sends an Authorization Challenge Request ({{challenge-request}}) to the Authorization Challenge Endpoint ({{authorization-challenge-endpoint}}) including the username.
* The Authorization Server returns an Error Response ({{challenge-error-response}}) including `"error": "authorization_required"`, `"device_session"`, and a custom error code indicating that an e-mail address must be collected.
* The Client collects an e-mail address from the user.
* The Client sends the e-mail address as part of a second Authorization Challenge Request to the Authorization Challenge Endpoint, along with the `device_session` parameter.
* The Authorization Server sends a verification code to the e-mail address and returns an Error Response including `"error": "authorization_required"`, `"device_session"` and a custom error code indicating that an e-mail verification code must be entered.
* The Client presents a user experience guiding the user to copy the e-mail verification code to the Client. Once the e-mail verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the e-mail verification code as well as the `device_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `device_session` to maintain the session context, and verifies the e-mail verification code. It determines that it also needs a phone number for account recovery purposes and returns an Error Response including `"error": "authorization_required"`, `"device_session"` and a custom error code indicating that a phone number must be collected.
* The Client collects a mobile phone number from the user.
* The Client sends the phone number in an Authorization Challenge Request to the Authorization Challenge Endpoint, along with the `device_session`.
* The Authorization Server uses the `device_session` parameter to link the previous requests. It sends a confirmation code to the phone number and returns an Error Response including `"error": "authorization_required"`, `"device_session"` and a custom error code indicating that a SMS confirmation code must be entered.
* The Client presents a user experience guiding the user to enter the SMS confirmation code. Once the SMS verification code is entered, the Client sends an Authorization Challenge Request to the Authorization Challenge Endpoint, including the confirmation code as well as the `device_session` parameter returned in the previous Error Response.
* The Authorization Server uses the `device_session` to maintain the session context, and verifies the SMS verification code before issuing an Authorization Code to the Client.
* The Client sends the Authorization Code in a Token Request ({{token-request}}) to the Token Endpoint.
* The Authorization Server verifies the Authorization Code and issues the requested tokens.

# Example Implementation

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
      "device_session": "ce6772f5e07bc8361572f"
    }

The client prompts the user for an OTP, and sends a new Authorization Challenge Request.

    POST /authorize HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    device_session=ce6772f5e07bc8361572f
    &otp=555121

The Authorization Server validates the `device_session` to find the expected user, then validates the OTP for that user, and responds with an authorization code.


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


# Acknowledgments
{:numbered="false"}

TODO acknowledge.
