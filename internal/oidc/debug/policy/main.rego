package envoy.authz

default allow = false

import input.attributes.request.http as http_request


allow {
    http_request.method == "GET"
    glob.match("/yes*", [], http_request.path)
}
