package app.rbac

default allow = false

allow {
    input.action == "read"
    input.resource == "finance"
    input.user == "finance_user"
}
