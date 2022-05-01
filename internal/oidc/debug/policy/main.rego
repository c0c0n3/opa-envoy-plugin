package envoy.authz

import input.attributes.request.http as http_request


# `allow` is the expression we return to the OPA Envoy Plugin.
# The plugin interprets it as follows:
#
# 1. `allow = true` or `allow = { allowed: true, ... }` where `...`
#    stands for any other key-value pair recognised by the plugin.
#    Forward the request upstream, possibly tweaking it depending
#    on the content of `...` if any.
# 2. `allow = { allowed: false,  realm: tenant, ... }` where `...`
#    stands for any other key-value pair recognised by the plugin.
#    Don't forward the request upstream, redirect the downstream
#    client to tenant's login URL as specified in the OIDC config.
#    This will trigger the Authorization Code flow and typically
#    only makes sense when the downstream client is a browser.
# 3. In all other cases, don't forward the request upstream and
#    return an error to the client, possibly tweaking the client
#    response if `allow = { ... }` where `...` are key-value pairs
#    recognised by the plugin.

default allow = false

allow = true {
    [authorize, _, _] := decision
    authorize == true
}

allow = { "allowed": false,  "realm": tenant } {
    [authorize, redirect, tenant] := decision
    authorize == false
    redirect == true
}


# Run the policies to find out what to do.
# To keep things simple, we expect all the policies to follow the same
# pattern. Each policy should have a `decision` rule returning an array
# with three elements in the following order:
#
# 1. Authorize flag. True if the policy allows the action to go ahead,
#    false otherwise.
# 2. Redirect flag. True if the downstream client should be redirected
#    to the tenant's login page when the authorize flag is false. This
#    flag is ignored if the authorize flag is true.
# 3. Tenant name. The name of the realm to use to look up the OIDC URL
#    and credentials needed to carry out the OIDC Authorization Code
#    flow. (This data is in the OPA Plugin OIDC config file.)
#
# Policies should be mutually exclusive depending on request path,
# i.e. at most one policy should apply to a given request path. So
# the policy's decision rule should look something like
#
#     decision = [authorize, redirect, tenant] {
#         is_policy_path
#         ...
#     }
#
# where `is_policy_path` is true just in case the policy is applicable
# to the request path. This way, when `is_policy_path` is false, OPA
# will discard `decision`. We actually enforce policies to be mutually
# exclusive below where we define our own `decision` rule incrementally
# from each imported policy module. If two `decision` rules coming from
# two separate modules happen to have a body that evaluates to true,
# OPA will abort evaluation with an error message:
#
#     complete rules must not produce multiple outputs
#


# Policy for resources at a path starting with `/yes`.
# Authorise any GET request, never redirect, don't care about tenants.
# Example:
#
#     $ curl -v localhost:8000/api/yes
#
# The `allow` rule above should evaluate to true.
#
decision = [authorize, redirect, tenant] {
    http_request.method == "GET"
    glob.match("/yes*", [], http_request.path)

    authorize := true
    redirect := false
    tenant := ""
}

# Policy for resources at a path starting with `/api`.
# - Authorise: any request to a path starting with `/api/yes` but deny
#   requests to any other path starting with `/api`
# - Redirect: never
# - Tenant: extract from 'tenant' header
#
# Example: Authorise.
#
#     $ curl -v localhost:8000/api/yes -H 'tenant: tenantB'
#
# The `allow` rule above should evaluate to true.
#
# Example: Deny.
#
#     $ curl -v localhost:8000/api/no -H 'tenant: tenantB'
#
# The `allow` rule above should evaluate to false. Ditto if the tenant
# header is missing.
#
decision = [authorize, redirect, tenant] {
    regex.match("^/api/.*", http_request.path)

    authorize := regex.match("/.*/yes.*", http_request.path)
    redirect := false
    tenant := http_request.headers["tenant"]
}

# Policy for resources at a path starting with `/ui`.
# - Authorise: any request to a path starting with `/ui/x/yes` where
#   `x` is a tenant name but deny requests to any other path starting
#   with `/ui`
# - Redirect: always
# - Tenant: extract from request path (second path element)
#
# Example: Authorise.
#
#     $ curl -v localhost:8000/ui/tenantA/yes
#
# The `allow` rule above should evaluate to true.
#
# Example: Deny.
#
#     $ curl -v localhost:8000/ui/tenantA/no
#
# The `allow` rule above should evaluate to
#
#     { allowed: false, realm: tenantA }
#
# plus the downstream response should be a 303 with a location header.
#
decision = [authorize, redirect, tenant] {
    regex.match("^/ui/[^/]+/.*", http_request.path)

    authorize := regex.match("/.*/yes.*", http_request.path)
    redirect := true
    tenant := split(http_request.path, "/")[2]
}
