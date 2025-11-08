module("luci.controller.tcpdump", package.seeall)

function index()
    entry({"admin", "services", "tcpdump"}, alias("admin", "services", "tcpdump", "status"), _("TCPDump"), 60)
    entry({"admin", "services", "tcpdump", "status"}, template("tcpdump/status"), _("状态"), 1)
    entry({"admin", "services", "tcpdump", "ajax_status"}, call("action_ajax_status"))
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_get_interfaces"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))
end

-- 配置常量
local config = {
    capture_file = "/tmp/tcpdump.pcap",
    process_pattern = "tcpdump -i .* -w /tmp/tcpdump.pcap",
    max_filesize = 100 -- MB
}

-- [优化] 统一的工具函数
local function is_process_running()
    local util = require "luci.util"
    local pid = util.exec("pgrep -f '" .. config.process_pattern .. "' 2>/dev/null"):match("%d+")
    return pid ~= nil, pid
end

local function file_exists(filepath)
    local nixio = require "nixio"
    return nixio.fs.access(filepath)
end

local function get_file_size(filepath)
    local nixio = require "nixio"
    local attr = nixio.fs.stat(filepath)
    return attr and attr.size or 0
end

-- [优化] 改进的接口获取
function action_get_interfaces()
    local sys = require "luci.sys"
    local util = require "luci.util"
    local interfaces = {}
    
    -- 方法1: 使用luci.sys获取网络设备
    local net_devices = sys.net.devices()
    if net_devices and #net_devices > 0 then
        for _, iface in ipairs(net_devices) do
            if iface ~= "lo" and not iface:match("^ifb") then
                table.insert(interfaces, iface)
            end
        end
    else
        -- 方法2: 备用方法，使用ip命令
        local ip_output = util.exec("ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1")
        for iface in ip_output:gmatch("[%w%-%.]+") do
            if iface ~= "lo" and not iface:match("^ifb") then
                table.insert(interfaces, iface)
            end
        end
    end
    
    -- [优化] 过滤虚拟接口并排序
    local physical_interfaces = {}
    for _, iface in ipairs(interfaces) do
        if not iface:match("^%w+%.%d+") then -- 过滤VLAN虚拟接口
            table.insert(physical_interfaces, iface)
        end
    end
    
    table.sort(physical_interfaces)
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(physical_interfaces)
end

-- [优化] 改进的状态检查
function action_ajax_status()
    local running, pid = is_process_running()
    local exists = file_exists(config.capture_file)
    local file_size = 0
    local file_size_human = "0 KB"
    
    if exists then
        file_size = get_file_size(config.capture_file)
        if file_size > 0 then
            file_size_human = tostring(math.floor(file_size / 1024)) .. " KB"
        else
            file_size_human = "0 KB"
        end
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json({ 
        running = running, 
        pid = pid,
        file_exists = exists,
        file_size = file_size,
        file_size_human = file_size_human
    })
end

-- [安全优化] 改进的命令构建
function action_start()
    local http = require "luci.http"
    local util = require "luci.util"
    local sys = require "luci.sys"
    
    local result = { success = false }
    
    -- 检查是否已在运行
    local running, current_pid = is_process_running()
    if running then
        result.message = "抓包正在进行中 (PID: " .. current_pid .. ")"
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    -- [安全] 输入验证和清理
    local interface = http.formvalue("interface") or "br-lan"
    interface = interface:gsub("[^%w%-_%.]", "")
    if interface == "" then 
        interface = "br-lan" 
    end
    
    -- 验证接口是否存在
    local interfaces_valid = {}
    for _, iface in ipairs(sys.net.devices()) do
        if iface ~= "lo" then
            table.insert(interfaces_valid, iface)
        end
    end
    
    local interface_exists = false
    for _, valid_iface in ipairs(interfaces_valid) do
        if valid_iface == interface then
            interface_exists = true
            break
        end
    end
    
    if not interface_exists then
        result.message = "接口不存在: " .. interface
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    -- 文件大小限制
    local filesize_opt = ""
    local filesize = http.formvalue("filesize") or ""
    if filesize and filesize ~= "" then
        local num = tonumber(filesize)
        if num and num > 0 and num <= config.max_filesize then
            filesize_opt = " -C " .. tostring(math.floor(num))
        else
            result.message = "文件大小必须在 1-" .. config.max_filesize .. " MB 之间"
            luci.http.prepare_content("application/json")
            luci.http.write_json(result)
            return
        end
    end
    
    -- 过滤器安全处理
    local filter = http.formvalue("filter") or ""
    local filter_opt = ""
    if filter and filter ~= "" then
        -- 更严格的过滤器验证
        if filter:match("^[%w%s%.:/%+-=!~%*&|<>()%[%]]+$") then
            filter = filter:gsub("'", "'\\''")
            filter_opt = " '" .. filter .. "'"
        else
            result.message = "过滤器包含非法字符"
            luci.http.prepare_content("application/json")
            luci.http.write_json(result)
            return
        end
    end
    
    -- 停止任何可能正在运行的实例
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 1")
    
    -- [优化] 构建并执行命令
    local cmd = string.format("tcpdump -i %s -w %s%s%s 2>/dev/null &", 
        interface, config.capture_file, filesize_opt, filter_opt)
    
    local exit_code = os.execute(cmd)
    
    -- 等待进程启动
    util.exec("sleep 2")
    
    -- 检查是否启动成功
    local running, new_pid = is_process_running()
    if running then
        result.success = true
        result.message = "抓包已启动 (PID: " .. new_pid .. ")"
        result.pid = new_pid
    else
        -- [优化] 尝试获取错误信息
        local test_cmd = string.format("timeout 2 tcpdump -i %s -c 1 %s 2>&1", interface, filter_opt)
        local test_output = util.exec(test_cmd)
        local error_msg = test_output:match("tcpdump: (.+)") or "未知错误，请检查过滤器语法或接口状态"
        result.message = "进程启动失败: " .. error_msg
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- [优化] 改进的停止功能
function action_stop()
    local util = require "luci.util"
    local result = { success = false }
    
    local running, pid = is_process_running()
    if not running then
        result.success = true
        result.message = "没有正在运行的抓包进程"
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    -- 先尝试正常停止
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 3")
    
    -- 检查是否停止
    running, pid = is_process_running()
    if not running then
        result.success = true
        result.message = "抓包已正常停止"
    else
        -- 强制停止
        os.execute("killall -9 tcpdump 2>/dev/null")
        util.exec("sleep 1")
        
        running, pid = is_process_running()
        if not running then
            result.success = true
            result.message = "抓包已强制停止"
        else
            result.message = "停止失败，进程可能处于僵尸状态"
        end
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- [优化] 改进的文件下载
function action_download()
    local http = require "luci.http"
    local nixio = require "nixio"
    
    if not file_exists(config.capture_file) then
        http.status(404, "文件不存在")
        return
    end
    
    -- 获取文件大小
    local file_size = get_file_size(config.capture_file)
    if file_size == 0 then
        http.status(500, "文件为空")
        return
    end
    
    http.header('Content-Type', 'application/vnd.tcpdump.pcap')
    http.header('Content-Disposition', 'attachment; filename="tcpdump_capture.pcap"')
    http.header('Content-Length', tostring(file_size))
    
    -- [优化] 使用nixio进行流式传输，支持大文件
    local fd = nixio.open(config.capture_file, "r")
    if fd then
        local chunk_size = 8192
        while true do
            local chunk = fd:read(chunk_size)
            if not chunk or #chunk == 0 then break end
            http.write(chunk)
        end
        fd:close()
    else
        http.status(500, "无法读取文件")
    end
end

-- [优化] 改进的文件删除
function action_delete()
    local result = { success = false }
    
    -- 确保没有抓包进程在运行
    local running, pid = is_process_running()
    if running then
        result.message = "请先停止抓包进程"
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    if file_exists(config.capture_file) then
        local ok, err = os.remove(config.capture_file)
        if ok then
            result.success = true
            result.message = "抓包文件已删除"
        else
            result.message = "删除文件失败: " .. (err or "未知错误")
        end
    else
        result.success = true
        result.message = "文件不存在"
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
