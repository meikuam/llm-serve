local jwt = require("resty.jwt")
local cjson = require("cjson")

local secret = os.getenv("WEBUI_SECRET_KEY")
if not secret then
    ngx.log(ngx.ERR, "WEBUI_SECRET_KEY is not set")
    ngx.exit(500)
end

local token = ngx.var.cookie_token
if not token then
    local auth_header = ngx.var.http_authorization
    if auth_header then
        local _, _, t = string.find(auth_header, "^Bearer%s+(.+)$")
        token = t
    end
end

if not token then
    ngx.log(ngx.ERR, "No token found in cookie or Authorization header")
    ngx.exit(401)
end

local jwt_obj = jwt:verify(secret, token, { algorithms = { "HS256" } })

if not jwt_obj.verified then
    ngx.log(ngx.ERR, "JWT verification failed: ", jwt_obj.reason)
    ngx.exit(401)
end

ngx.req.set_header("X-User-Id", jwt_obj.payload.sub or "")
ngx.req.set_header("X-User-Email", jwt_obj.payload.email or "")
