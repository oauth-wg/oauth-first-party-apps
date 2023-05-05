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
 - next generation
 - unicorn
 - sparkling distributed ledger
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
  RFC8259:

informative:


--- abstract

This document extends the OAuth 2.0 Authorization Framework {{RFC6749}} with
new grant types to support first-party native applications that want to control the user experience of the process of obtaining authorization from the user.

In many cases, this can provide an entirely browserless experience suited for native
applications, only delegating to the browser in unexpected, high risk, or error conditions.

While a fully-delegated approach using the redirect-based Authorization Code grant is generally
preferred, this draft provides a mechanism for the client to directly interact
with the user. This requires a high degree of trust between the authorization server
and the client, as there typically is for first-party applications.
It should only be considered when there are usability
concerns with a redirect-based approach, such as for native mobile or desktop applications.


--- middle

# Introduction



TODO: Key points to address include problem description, the relationship to the step-up authentication spec (use of acr etc.), properties of the protocol (extensibility etc).


## Usage and Applicability

TODO: Prerequisites for using this specification

* MUST only be used by first-party applications, when the authorization server and application are operated by the same entity and the user understands them both as the same entity.
* MUST NOT be used by third party applications, SHOULD take measures to prevent use by third party applications. (e.g. only enable for certain client IDs, and take measures to authenticate your apps.)
* Designed for native applications, both mobile and desktop applications.
* SHOULD only use this specification if there is only one native application (per platform) for the service. If there are multiple applications, then a traditional redirect-based authorization code flow SHOULD be used instead.

## Limitations of this specification

TODO

* If the service provides multiple applications, then it creates an additional burden to build and maintain native login flows within each application. Instead, the redirect-based authorization code flow removes the burden of implementing login flows from each application by centralizing all aspects of logging in at the authorization server.
* See {{phishing}} section below.


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

Three entry points into the draft:

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
             |          | (F) Authorization     |                   |
             |          |     Grant             |+-----------------+|
             |          |---------------------->||      Token      ||
             |          |                       ||     Endpoint    ||
             |          |<----------------------||                 ||
             |          | (G) Access Token      |+-----------------+|
             |          |                       |                   |
             +----------+                       +-------------------+
~~~
Figure: Native Client Authorization Code Request

- (A) The native client collects information from the user.
- (B) The client initiates the authorization by making a POST request to the authorization challenge endpoint, potentially with information collected from the user (e.g. password)
- (C) The authorization server determines whether the information provided to the Authorization Challenge Endpoint is sufficient to grant authorization, and either responds with an authorization code or responds with an error. In this example, it determines that additional information is needed and responds with an error. The error may contain additional information to guide the Client on what information to collect next. This pattern of collecting information, submitting it to the Authorization Challenge Endpoint and then receing an error or authroization code may repeat several times.
- (D) The client gathers additional information and POST a request to the authorization challenge endpoint.
- (E) The authorization challenge endpoint returns a authorization code.
- (F) The native client sends the authroizations code received in step (E) to obtain a token from the Token Endpoint.
- (G) The Authroization Server returns an Access Token from the Token Endpoint.

From scratch:

1. The client initiates the authorization by making a POST request to the authorization challenge endpoint, potentially with information collected from the user (e.g. password)
1. The authorization server determines whether the information provided to the authorization initiation endpoint is sufficient to grant authorization, and either responds with an authorization code or responds with an error
1. The client continues to collect information from the user and send it to the authorization challenge endpoint until it receives an authorization code
1. The client exchanges the authorization code for an access token at the token endpoint



When sending a refresh token to the token endpoint:

1. When using a refresh token, the authorization server MAY respond with an error to indicate that re-authorization of the user is required

When using an access token at the resource server:

1. When making a resource request to a resource server, the resource server MAY respond with an error according to OAuth 2.0 Step-Up Authentication Challenge Protocol


# Protocol Endpoints

## Authorization challenge endpoint

The authorization challenge endpoint is a new endpoint defined by this specification which the native application uses to obtain an authorization code.

The client initiates the authorization flow with or without information collected from the user (e.g. a password or MFA code).

The authorization challenge endpoint response is either an authorization code or an error code, and may also contain a `device_session` which the client uses on subsequent requests to the authorization challenge endpoint.


## Token endpoint

The token endpoint is used by the client to obtain an access token by
presenting its authorization grant or refresh token, as described in
Section 3.2 of OAuth 2.0 {{RFC6749}}.

This specification extends the token endpoint response to allow the authorization
server to indicate that further authentication of the user is required.


# Authorization Initiation {#authorization-initiation}

A client may wish to initiate an authorization flow by first prompting the user for their user identifier or other account information. The authorization challenge endpoint is a new endpoint to collect this login hint and direct the client with the next steps, whether that is to do an MFA flow, or perform an OAuth redirect-based flow.

## Authorization Challenge Request

The client makes a request to the authorization challenge endpoint by adding the
following parameters using the `application/x-www-form-urlencoded
format with a character encoding of UTF-8 in the HTTP request body:

"client_id":
: REQUIRED if the client is not authenticating with the
  authorization server.

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

## Authorization Challenge Response

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


### Error Response

If the request contains invalid parameters or incorrect data,
the authorization server responds with an HTTP 400 (Bad Request)
status code (unless specified otherwise) and includes the following
parameters with the response:

"error":
:    REQUIRED.  A single ASCII [USASCII] error code from the following:

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

     TODO: The authorization server MAY extend these error codes with custom
     messages based on the requirements of the authorization server.

"error_description":
:    OPTIONAL.  Human-readable ASCII [USASCII] text providing
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

# Token Request

The client makes a request to the token endpoint using the authorization code it obtained from the authorization challenge endpoint, according to Section 4.1.3 of {{RFC6749}}.

TODO: Would it be better to define our own grant type instead of overloading the authorization code grant type? Probably, since there won't be a redirect_uri.

TODO: In any case, document the parameters here.

## Token Endpoint Error Response

Upon any request to the token endpoint, including a request with a valid refresh token,
the authorization server can respond with an authorization challenge instead of a successful access token response.

An authorization challenge error response is a particular type of
error response as defined in Section 5.2 of OAuth 2.0 {{RFC6749}} where
the error code is set to the following value:

(TODO: This value needs a better name)

"authorization_required":
: The authorization grant is insufficiently authorized, but another
  access token request may succeed if an additional authorization
  grant is presented.

"device_session":
:    OPTIONAL.  The device session allows the authorization server to
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

Step-Up Authentication defines a mechanism for resource servers to tell the client to start a new authorization request, including `acr_values` and `max_age`, and `scope` from RFC6750. Upon receiving this request, the client starts a new authorization request according to this specification, and includes the `acr_values`, `max_age` and `scope` returned in the error response.

(No new things need to be defined by this specification in order to use this.)


# Security Considerations

## First-Party Applications

Because this specification enables a client application to interact directly with the end user, and the application handles sending any information collected from the user to the authorization server, it is expected to be used only for first-party applications when the authorization server also has a high degree of trust of the client.

First-party applications are applications that the user recognizes as belonging to the same brand as the authorization server. For example, a bank publishing their own mobile application.

## Phishing {#phishing}

There are two ways using this specification increases the risk of phishing.

With this specification, the client interacts directly with the end user, collecting information provided by the user and sending it to the authorization server. If an attacker impersonates the client and successfully tricks a user into using it, they may not realize they are giving their credentials to the malicious application.

In a traditional OAuth deployment using the redirect-based authorization code flow, the user will only ever enter their credentials at the authorization server, and it is straightforward to explain to avoid entering credentials in other "fake" websites. By introducing a new place the user is expected to enter their credentials using this specification, it is more complicated to teach users how to recognize other fake login prompts that might be attempting to steal their credentials.

Because of these risks, the authorization server MAY decide to require that the user go through a redirect-based flow at any stage of the process based on its own risk assessment.


## Client Authentication

Typically, mobile and desktop applications are considered "public clients" in OAuth, since they cannot be shipped with a statically configured set of client credentials. Because of this, client impersonation should be a concern of anyone deploying this pattern. Without client authentication, a malicious user or attacker can mimick the requests the application makes to the authorization server, pretending to be the legitimate client.

Because this specification is intended for first-party applications, it is likely that the intent is to also avoid prompting the user with a consent screen as recommended by {{RFC6749}}.

Implementers SHOULD consider additional measures to limit the risk of client impersonation, such as using attestation APIs available from the operating system.

## Proof of Possession

TODO: Describe how to add proof of possession into the various parts of this flow. Describe why, because things like device session could otherwise be swapped in various types of attacks.

* PoP binding of device session parameter
* The client SHOULD use DPoP for every request, the AS SHOULD bind any artifacts returned to the DPoP key


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
