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

TODO: Mention the trust prerequisites for this to be useful. Absolutely not allowed for third-party apps. Designed for native apps, specifically first-party, when the AS and app are operated by the same entity, and the user understands them both as the same entity...


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

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
