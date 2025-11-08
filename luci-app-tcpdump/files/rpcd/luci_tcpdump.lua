local fs = require "nixio.fs"
local sys = require "nixio".sys

local PID_FILE = "/tmp/tcpdump.pid"
local LOG_FILE = "/tmp/tcpdump.log"
local CAP_FILE = "/tmp/tcpdump.pcap"

local function validate_interface(ifname)
    if not ifname or ifname == "" then
        return "br-lan"
    end
    if ifname:match("[^a-zA-Z0-9%._%-]") then
        return "br-lan"
    end
    return ifname
end

local function validate_filter(filter)
    if not filter or filter == "" then
        return ""
    end
    local safe_filter = filter:gsub("[^a-zA-Z0-9%.:/,()=]", "")
    return safe_filter
end

local function is_running()
    local pid = fs.readfile(PID_FILE)
    if pid and pid:match("^%d+$") then
        return fs.stat("/proc/" .. pid) ~= nil
    end
    return false
end

local function start_capture(interface, filter, filesize)
    if is_running() then
        return { error = "tcpdump is already running." }
    end

    local safe_if = validate_interface(interface)
    local safe_filter = validate_filter(filter)

    local size_opt = ""
    if filesize and tonumber(filesize) and tonumber(filesize) > 0 then
        size_opt = "-C " .. tonumber(filesize)
    end

    local filter_opt = ""
    if safe_filter and safe_filter ~= "" then
        filter_opt = safe_filter
    end

    local command = string.format(
        "tcpdump -i %s %s -U -s 0 -w %s %s >%s 2>&1 & echo $! > %s",
        safe_if,
        size_opt,
        CAP_FILE,
        filter_opt,
        LOG_FILE,
        PID_FILE
    )

    local ok = os.execute(command)
    if ok then
        return { success = true }
    else
        return { error = "Failed to start tcpdump" }
    end
end

local function stop_capture()
    local pid = fs.readfile(PID_FILE)
    if pid and pid:match("^%d+$") and is_running() then
        os.execute("kill " .. pid)
    end

    fs.unlink(PID_FILE)
    fs.unlink(CAP_FILE)
    fs.unlink(LOG_FILE)

    return { success = true }
end

local function get_status()
    if is_running() then
        return { running = true, pid = fs.readfile(PID_FILE) or "" }
    else
        return { running = false }
    end
end

return {
    start = start_capture,
    stop = stop_capture,
    status = get_status
}
