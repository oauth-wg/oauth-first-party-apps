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

TODO Abstract


--- middle

# Introduction

TODO Introduction


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
