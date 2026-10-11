# IPScanner Forward Auth

A small gate that checks every visitor with the [IPScanner](https://ipscanner.io) edge check before the request reaches your app. One container for nginx, Nginx Proxy Manager, Traefik, Caddy, HAProxy and Apache.

- **Forward auth** (`/check`): your proxy asks the gate about each request. `200` allows it with `X-IPScanner-*` headers for your app, `403` blocks it. For nginx `auth_request`, Nginx Proxy Manager, Traefik `ForwardAuth` and Caddy `forward_auth`.
- **Proxy mode** (`UPSTREAM_URL`): the gate sits in front of your app and forwards allowed requests. For HAProxy, Apache and anything without forward auth.
- **Monitor mode** (default) only adds headers. **Enforce mode** blocks.
- With `SITE_ID`, mode and per class policy come from the [IPScanner dashboard](https://ipscanner.io/dashboard/sites).
- Verified crawlers always pass. Checks are cached per visitor and fail open: if the API is slow or down, requests go through.

Static binary, about 4 MB image (`linux/amd64`, `linux/arm64`), runs as non-root, no shell.

## Run

1. Create an API key at [ipscanner.io](https://ipscanner.io).
2. Add the gate next to your proxy, on the same Docker network:

```yaml
services:
  ipscanner:
    image: ghcr.io/ipscanner/forward-auth:0.1
    restart: unless-stopped
    environment:
      IPSCANNER_API_KEY: ${IPSCANNER_API_KEY}
      SITE_ID: site_...
```

Do not publish its port: only your proxy should reach it (see [Client IP](#client-ip)). Then add one of the snippets below. Without a key every request passes unchecked.

The same image is on Docker Hub as `ipscanner/forward-auth`. Binaries for Linux and macOS are on the [releases page](https://github.com/ipscanner/ipscanner-forward-auth/releases).

## nginx

`auth_request` (in the official nginx image and most distributions):

```nginx
location / {
    auth_request /_ipscanner;
    auth_request_set $ipscanner_status     $upstream_http_x_ipscanner_status;
    auth_request_set $ipscanner_class      $upstream_http_x_ipscanner_class;
    auth_request_set $ipscanner_action     $upstream_http_x_ipscanner_action;
    auth_request_set $ipscanner_network    $upstream_http_x_ipscanner_network_class;
    auth_request_set $ipscanner_anonymized $upstream_http_x_ipscanner_anonymized;
    auth_request_set $ipscanner_risk       $upstream_http_x_ipscanner_risk;
    auth_request_set $ipscanner_country    $upstream_http_x_ipscanner_country;
    auth_request_set $ipscanner_site       $upstream_http_x_ipscanner_site;
    auth_request_set $ipscanner_request_id $upstream_http_x_ipscanner_request_id;
    error_page 403 = @ipscanner_blocked;

    proxy_set_header X-IPScanner-Status        $ipscanner_status;
    proxy_set_header X-IPScanner-Class         $ipscanner_class;
    proxy_set_header X-IPScanner-Action        $ipscanner_action;
    proxy_set_header X-IPScanner-Network-Class $ipscanner_network;
    proxy_set_header X-IPScanner-Anonymized    $ipscanner_anonymized;
    proxy_set_header X-IPScanner-Risk          $ipscanner_risk;
    proxy_set_header X-IPScanner-Country       $ipscanner_country;
    proxy_set_header X-IPScanner-Site          $ipscanner_site;
    proxy_set_header Host                      $host;
    proxy_set_header X-Forwarded-For           $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto         $scheme;
    proxy_pass http://app:80;
}

location = /_ipscanner {
    internal;
    proxy_pass http://ipscanner:8080/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_connect_timeout 1s;
    proxy_read_timeout 5s;
    error_page 500 502 503 504 = @ipscanner_down;
}

location @ipscanner_down {
    return 204;
}

location @ipscanner_blocked {
    internal;
    proxy_method GET;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-IPScanner-Request-Id $ipscanner_request_id;
    rewrite ^ /blocked break;
    proxy_pass http://ipscanner:8080;
}
```

`@ipscanner_down` lets requests through when the gate itself is unreachable. `@ipscanner_blocked` shows the gate's 403 page with the request ID. nginx resolves `ipscanner` at startup, so start the gate first.

## Nginx Proxy Manager

Put the gate on NPM's Docker network, then paste this into the proxy host's **Advanced** tab. NPM leaves out its own `location /` when the Advanced text has one.

```nginx
location / {
    auth_request /_ipscanner;
    auth_request_set $ipscanner_status     $upstream_http_x_ipscanner_status;
    auth_request_set $ipscanner_class      $upstream_http_x_ipscanner_class;
    auth_request_set $ipscanner_action     $upstream_http_x_ipscanner_action;
    auth_request_set $ipscanner_network    $upstream_http_x_ipscanner_network_class;
    auth_request_set $ipscanner_anonymized $upstream_http_x_ipscanner_anonymized;
    auth_request_set $ipscanner_risk       $upstream_http_x_ipscanner_risk;
    auth_request_set $ipscanner_country    $upstream_http_x_ipscanner_country;
    auth_request_set $ipscanner_site       $upstream_http_x_ipscanner_site;
    auth_request_set $ipscanner_request_id $upstream_http_x_ipscanner_request_id;
    error_page 403 = @ipscanner_blocked;

    proxy_set_header X-IPScanner-Status        $ipscanner_status;
    proxy_set_header X-IPScanner-Class         $ipscanner_class;
    proxy_set_header X-IPScanner-Action        $ipscanner_action;
    proxy_set_header X-IPScanner-Network-Class $ipscanner_network;
    proxy_set_header X-IPScanner-Anonymized    $ipscanner_anonymized;
    proxy_set_header X-IPScanner-Risk          $ipscanner_risk;
    proxy_set_header X-IPScanner-Country       $ipscanner_country;
    proxy_set_header X-IPScanner-Site          $ipscanner_site;
    include conf.d/include/proxy.conf;
}

location = /_ipscanner {
    internal;
    proxy_pass http://ipscanner:8080/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_connect_timeout 1s;
    proxy_read_timeout 5s;
    error_page 500 502 503 504 = @ipscanner_down;
}

location @ipscanner_down {
    return 204;
}

location @ipscanner_blocked {
    internal;
    proxy_method GET;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-IPScanner-Request-Id $ipscanner_request_id;
    rewrite ^ /blocked break;
    proxy_pass http://ipscanner:8080;
}
```

## Traefik

Docker labels on your app (Coolify: add them under the app's container labels):

```yaml
labels:
  traefik.http.middlewares.ipscanner.forwardauth.address: http://ipscanner:8080/check
  traefik.http.middlewares.ipscanner.forwardauth.trustForwardHeader: "true"
  traefik.http.middlewares.ipscanner.forwardauth.authResponseHeadersRegex: (?i)^x-ipscanner-
  traefik.http.routers.app.middlewares: ipscanner
```

`trustForwardHeader` passes on an `X-Forwarded-For` chain only when the entry point already trusts the sender (`forwardedHeaders.trustedIPs`), otherwise Traefik drops it first. Traefik also has a [plugin](https://github.com/ipscanner/ipscanner-traefik) that runs inside Traefik without this container.

## Caddy

```caddyfile
example.com {
	forward_auth ipscanner:8080 {
		uri /check
		copy_headers X-IPScanner-Status X-IPScanner-Class X-IPScanner-Action X-IPScanner-Network-Class X-IPScanner-Anonymized X-IPScanner-Risk X-IPScanner-Country X-IPScanner-Site
	}
	reverse_proxy app:80
}
```

There is also a [Caddy module](https://github.com/ipscanner/ipscanner-caddy) that runs inside Caddy.

## HAProxy

Run the gate in proxy mode with `UPSTREAM_URL=http://app:80` and send traffic through it. The app is the backup server, so traffic still flows when the gate is down.

```haproxy
frontend web
    bind :80
    option forwardfor
    http-request del-header ^x-ipscanner- -m reg
    default_backend ipscanner

backend ipscanner
    option httpchk GET /healthz
    server gate ipscanner:8080 check inter 2s fall 2 rise 1
    server app app:80 backup
```

## Apache

Proxy mode as for HAProxy (`UPSTREAM_URL=http://app:80`), with the app as a hot standby:

```apache
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule slotmem_shm_module modules/mod_slotmem_shm.so
LoadModule lbmethod_byrequests_module modules/mod_lbmethod_byrequests.so

<Proxy "balancer://ipscanner">
    BalancerMember "http://ipscanner:8080" retry=10 connectiontimeout=2
    BalancerMember "http://app:80" status=+H
</Proxy>
RequestHeader unset X-IPScanner-Status
RequestHeader unset X-IPScanner-Class
RequestHeader unset X-IPScanner-Action
RequestHeader unset X-IPScanner-Network-Class
RequestHeader unset X-IPScanner-Anonymized
RequestHeader unset X-IPScanner-Risk
RequestHeader unset X-IPScanner-Country
RequestHeader unset X-IPScanner-Site
ProxyPreserveHost On
ProxyPass        "/" "balancer://ipscanner/"
ProxyPassReverse "/" "balancer://ipscanner/"
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `IPSCANNER_API_KEY` | | Your API key. |
| `IPSCANNER_API_KEY_FILE` | | File holding the key (Docker secrets). Wins over `IPSCANNER_API_KEY`. |
| `SITE_ID` | | Site ID from the dashboard (`site_...`). Mode and policy then come from the dashboard. |
| `MODE` | `monitor` | `monitor` or `enforce`. With `SITE_ID`, only `monitor` has an effect: it keeps the gate in monitor mode whatever the dashboard says. |
| `BLOCK_CLASSES` | `malicious_automation` | Without `SITE_ID`: classes blocked in enforce mode, comma separated. Any of `malicious_automation`, `ai_agent`, `tor`, `vpn`, `proxy`, `hosting`, `relay`, or `none`. |
| `TRUSTED_PROXIES` | `private` | Addresses and CIDR ranges whose IP and URI headers are believed. `private` = private and loopback ranges, `cloudflare` = Cloudflare's edge, `none` = the peer address only. |
| `IP_HEADERS` | `X-Forwarded-For` | Headers read, in order, from a trusted proxy. |
| `TIMEOUT_MS` | `1500` | Budget for one check. On timeout the request passes. |
| `CACHE_TTL` | `600` | Seconds a verdict is reused per site, IP and User-Agent. |
| `CACHE_SIZE` | `10000` | Verdicts kept in memory. |
| `POLICY_TTL` | `30` | Seconds a site policy is reused. |
| `SKIP_PATHS` | static assets | Case insensitive regex on the path. Matching requests are not checked. Empty checks everything. |
| `UPSTREAM_URL` | | Turns on proxy mode: allowed requests go to this URL. |
| `LISTEN` | `:8080` | Listen address. |
| `HEALTH_PATH` | `/healthz` | Health endpoint. |
| `BLOCK_MESSAGE` | `Blocked by IPScanner edge guard.` | Text of the 403 page. |
| `IPSCANNER_API_URL` | `https://ipscanner.io` | API base URL. |
| `DEBUG` | `false` | One log line per decision; in proxy mode also `X-IPScanner-Status`, `-Class` and `-Action` on responses. |

`CACHE_TTL` and `POLICY_TTL` also take durations such as `10m`. Invalid values stop the gate at startup with a log line.

## Sites

1. Create a site in the [dashboard](https://ipscanner.io/dashboard/sites).
2. Set `SITE_ID`.

Mode and per class policy (`allow`, `flag` or `block`) then come from the dashboard and apply within `POLICY_TTL`. If a refresh fails, the last policy is used for up to 24 hours. A site with no policy lets every request pass. `monitor` never blocks: the action becomes `would_block` or `would_flag`. Verified crawlers always pass.

Without `SITE_ID`, `MODE` and `BLOCK_CLASSES` decide, and the network class counts too: with `vpn` blocked, a bot on a VPN is blocked.

## Headers

On `200` from `/check` (copy them to your app as above), and on the request to your app in proxy mode:

| Header | Example |
|---|---|
| `X-IPScanner-Status` | `ok`, `error`, `timeout`, `backoff` or `skipped` |
| `X-IPScanner-Class` | `human`, `verified_bot`, `ai_agent`, `malicious_automation`, `tor`, `vpn`, `proxy`, `hosting`, `relay` |
| `X-IPScanner-Action` | `allow`, `flag`, `block`, `would_flag`, `would_block` |
| `X-IPScanner-Network-Class` | `residential_clean`, `hosting`, `vpn`, `tor`, ... |
| `X-IPScanner-Anonymized` | `true` or `false` |
| `X-IPScanner-Risk` | `0` to `100` |
| `X-IPScanner-Country` | `DE` |
| `X-IPScanner-Site` | `site_...`, set with `SITE_ID` |

When a check fails or is skipped, only `X-IPScanner-Status` is set. In proxy mode, incoming `X-IPScanner-*` headers are removed so clients cannot send their own verdict; the snippets above do the same in the proxy.

## Endpoints

| Path | Mode | Answer |
|---|---|---|
| `/check` | forward auth | `200` with the headers above, or `403` with the block page and `X-IPScanner-Request-Id` |
| `/blocked` | forward auth | The `403` page for the request ID in `X-IPScanner-Request-Id` (nginx `error_page`) |
| `/healthz` | both | `200` JSON: version, mode, site, backoff, last error, cached policy |

`/check` reads the original request from the proxy's headers: `X-Forwarded-For` (or `IP_HEADERS`), `User-Agent`, `X-Forwarded-Uri` or `X-Original-URI`, `X-Forwarded-Method` or `X-Original-Method`. `OPTIONS` requests and `SKIP_PATHS` are never checked.

## Client IP

The visitor's address comes from `X-Forwarded-For` only when the peer is in `TRUSTED_PROXIES`, walking the chain from the nearest hop back to the first address that is not a trusted proxy. From anyone else the headers are ignored and the peer address is used.

The default, `private`, fits a proxy that talks to the gate over a Docker or private network. If the gate's port is reachable from elsewhere in that network, list your proxy's address instead. Private and loopback visitor addresses are never checked.

## Fail open

Every error lets the request through: on a timeout (`TIMEOUT_MS`) or API error checks pause for 30 seconds, after a 401, 402, 403 or 429 for 5 minutes. `/healthz` stays `200` and shows the backoff. If the gate itself is down, the nginx and NPM snippets let requests through (after the 1 s connect timeout), HAProxy sends them straight to the app, Apache does after the first failed request, and Traefik and Caddy answer with an error: run the gate with `restart: unless-stopped`.

## Logs

JSON lines on stdout: startup, shutdown, API failures and, with `DEBUG`, one line per decision with `ip`, `path`, `trafficClass`, `networkClass`, `decision`, `mode`, policy and cache. The API key is never logged. `SIGTERM` drains open requests for up to 10 seconds.

## Cost

Each uncached visitor costs one edge check (2 request units). Repeat requests within `CACHE_TTL` are free. The cache is in memory, per gate instance.

## Develop

```sh
go test -race ./...
docker build -t ipscanner-forward-auth .
IPSCANNER_KEY_FILE=/path/to/key IPSCANNER_E2E_SITE_HELPER=/path/to/site.cjs bash test/e2e/run.sh
```

The end to end run starts the gate behind nginx, the NPM config, Traefik, Caddy, HAProxy and Apache in Docker (ports 18100 to 18119) against an API on `IPSCANNER_API_URL` (default `http://localhost:3050`).

API reference: [ipscanner.io/api-documentation](https://ipscanner.io/api-documentation).

## License

MIT
