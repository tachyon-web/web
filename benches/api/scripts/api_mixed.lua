-- API Mixed Traffic Pattern
--
-- Simulates a realistic REST API workload. Traffic distribution based on
-- common API usage patterns (analytics, e-commerce, SaaS backends):
--
--   30%  GET /api/v1/users/:id          (fetch single resource)
--   15%  GET /api/v1/users/:id/posts    (nested resource list)
--   20%  POST /api/v1/users             (create — JSON body)
--   10%  PATCH /api/v1/users/:id        (partial update — JSON body)
--   10%  DELETE /api/v1/users/:id       (delete)
--   10%  GET /api/v1/search?q=...       (search + pagination)
--   3%   GET /api/v1/metrics            (heavy response)
--   2%   GET /health                    (health check / load balancer probe)
--
-- IDs are randomized per request to prevent caching and simulate realistic
-- primary-key distribution.

math.randomseed(os.time())

local json_create = '{"name":"Alice Rustacean","email":"alice@example.com","role":"user"}'
local json_patch   = '{"name":"Bob Updated","active":true}'

-- Weighted request slots (100 total for easy percentage reading)
-- Each slot is: { method, path_template, body_or_nil, content_type_or_nil }
local slots = {}

-- 30 × GET /users/:id
for _ = 1, 30 do
    slots[#slots+1] = { "GET", "/api/v1/users/ID", nil, nil }
end
-- 15 × GET /users/:id/posts
for _ = 1, 15 do
    slots[#slots+1] = { "GET", "/api/v1/users/ID/posts", nil, nil }
end
-- 20 × POST /users
for _ = 1, 20 do
    slots[#slots+1] = { "POST", "/api/v1/users", json_create, "application/json" }
end
-- 10 × PATCH /users/:id
for _ = 1, 10 do
    slots[#slots+1] = { "PATCH", "/api/v1/users/ID", json_patch, "application/json" }
end
-- 10 × DELETE /users/:id
for _ = 1, 10 do
    slots[#slots+1] = { "DELETE", "/api/v1/users/ID", nil, nil }
end
-- 10 × GET /search
for _ = 1, 10 do
    slots[#slots+1] = { "GET", "/api/v1/search?q=rust&page=1&per_page=20", nil, nil }
end
-- 3 × GET /metrics
for _ = 1, 3 do
    slots[#slots+1] = { "GET", "/api/v1/metrics", nil, nil }
end
-- 2 × GET /health
for _ = 1, 2 do
    slots[#slots+1] = { "GET", "/health", nil, nil }
end

local n = #slots

local counter = 0

function init(args)
    counter = (tonumber(args[1]) or 0) * 7
end

function request()
    counter = counter + 1
    local slot = slots[(counter % n) + 1]

    -- Replace "ID" placeholder with a random realistic primary key
    local id = math.random(1, 9999)
    local path = slot[2]:gsub("ID", tostring(id))

    local headers = {}
    if slot[4] then
        headers["Content-Type"] = slot[4]
    end

    local body = slot[3] or ""
    return wrk.format(slot[1], path, headers, body)
end

-- Optional: print per-thread summary on completion
function done(summary, latency, requests)
    io.write(string.format(
        "Requests: %d  Errors: %d  Timeouts: %d  Avg latency: %.2fms\n",
        summary.requests,
        summary.errors.status + summary.errors.connect + summary.errors.read + summary.errors.write,
        summary.errors.timeout,
        latency.mean / 1000.0
    ))
end
