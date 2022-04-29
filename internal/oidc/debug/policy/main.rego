package envoy.authz

import input.attributes.request.http as http_request


default allow = { "allowed": false }

allow = { "allowed": true, "realm": tenant } {
     tenant := action_allowed[_]
}

action_allowed[tenant] {
    http_request.method == "GET"
    glob.match("/yes*", [], http_request.path)
    tenant := ""
}

action_allowed[tenant] {
    http_request.method == "GET"
    regex.match("^/api/.*", http_request.path)
    tenant := http_request.headers["tenant"]
}

action_allowed[tenant] {
    http_request.method == "GET"
    regex.match("^/[^/]+/u(i|i/.*)", http_request.path)
    tenant := split(http_request.path, "/")[1]
}
