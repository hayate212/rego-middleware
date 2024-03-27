package app

import future.keywords.if

# リクエストのメソッド判定
GET if input.method == "GET"
POST if input.method == "POST"

# いかなる条件も満たさない場合はリクエストを許可しないためにデフォルトでfalseを返す
default allow := false

# Admin権限の場合は全てのリクエストを許可
allow if {
    input.role == "admin"
}

# GET HelloWolrd
allow if {
    GET
    input.path == "/"
}

# GET ユーザー一覧取得
allow if {
    GET
    input.path == "/users"
    
    # 許可するロールのリスト
    allow_roles := ["manager", "user"]
    # リクエストしてきたユーザーのロールが許可するロールのリストに含まれているか
    allow_roles[_] == input.role
}

# POST ユーザー登録
allow if {
    POST
    input.path == "/users"

    allow_roles := ["manager"]
    allow_roles[_] == input.role
}
