-- Static Mixed Traffic Pattern
--
-- Simulates realistic web traffic where the browser fetches an HTML page
-- and then all its sub-resources (CSS, JS, images) in parallel.
--
-- Distribution (approximate real-world CDN traffic):
--   40% HTML pages  (index.html, about.html equiv → all map to index.html)
--   25% JS bundles
--   20% CSS stylesheets
--   15% Images / binary assets
--
-- All requests are plain GET with no body.

local counter = 0

-- URL table for the target framework (port set by caller via BASE_URL env or wrk args)
local urls = {
    -- HTML pages (40%)
    "/index.html",
    "/index.html",
    "/index.html",
    "/index.html",
    -- JS (25%)
    "/script.js",
    "/script.js",
    "/script.js",
    -- CSS (20%)
    "/style.css",
    "/style.css",
    -- PNG / binary (15%)
    "/logo.png",
}

local n = #urls

-- wrk calls init() once per thread
function init(args)
    -- Each thread gets its own counter starting at an offset to avoid
    -- all threads hitting the same URL simultaneously.
    counter = (tonumber(args[1]) or 0) * 3
end

-- wrk calls request() for every request on this thread
function request()
    counter = counter + 1
    local url = urls[(counter % n) + 1]
    return wrk.format("GET", url)
end
