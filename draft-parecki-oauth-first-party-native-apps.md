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
* MUST NOT be used by third party applications, SHOULD take measures to prevent use by third party applications.
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

# Protocol Overview

TODO


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



# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
