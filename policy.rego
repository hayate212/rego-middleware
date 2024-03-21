package app

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow = false
default rule := null
allow if {
    rule
    authcheck
    count(missing_permissions) == 0
}

GET if input.method == "GET"
POST if input.method == "POST"
PUT if input.method == "PUT"
DELETE if input.method == "DELETE"

# 必要な権限の内、ユーザーが持っている権限のリスト
has_permissions contains x if {
    some x, input.permissions[_] in rule.permissions
}
# 不足している権限のリスト
default missing_permissions := {}
missing_permissions = x if {
    rule != null
    x := rule.permissions - has_permissions
}

# 
default authcheck = true
authcheck = x if {
    rule.auth
    x := input.auth
}

genrule(auth, permissions) := x if {
    x := {
        "auth": auth,
        "permissions": permissions
    }
}

# policy definitions
rule = x if {
    GET
    "/api/users" == input.path

    x := {
        "auth": true,
        "permissions": {"users:read"}
    }
}
rule = x if {
    POST
    "/api/users" == input.path

    x := {
        "auth": true,
        "permissions": {"users:create"}
    }
}
