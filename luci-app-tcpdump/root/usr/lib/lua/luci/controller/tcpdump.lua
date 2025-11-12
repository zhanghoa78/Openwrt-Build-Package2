local M = {}

-- 确保与旧系统兼容，通过全局module方法声明模块（如果可用）
if module then
    module("luci.controller.tcpdump", package.seeall)
end

-- 常用库的一次性导入
local http = require "luci.http"
local util = require "luci.util"
local nixio = require "nixio"

-- 常量定义
local CAPTURE_FILE = "/tmp/tcpdump.pcap"
local MAX_CAPTURE_SIZE = 50 * 1024 * 1024 -- 50MB的文件大小限制
local MAX_CAPTURE_DURATION = 3600 -- 最大捕获时长，1小时

function M.index()
    entry({"admin", "services", "tcpdump"}, firstchild(), _("TCPDump"), 60).dependent = false
    entry({"admin", "services", "tcpdump", "overview"}, template("tcpdump/overview"), _("Overview"), 1)
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_interfaces"))
    entry({"admin", "services", "tcpdump", "ajax_status"}, call("action_ajax_status"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))
end

-- 获取网络接口列表
function M.action_interfaces()
    local interfaces = {}
    local list = util.exec("ls /sys/class/net/ 2>/dev/null")

    if list and list ~= "" then
        -- 使用正确的gmatch按空格分割获取接口列表
        for iface in list:gmatch("[^%s]+") do
            iface = iface:match("^%s*(.-)%s*$")
            if iface ~= "" and iface ~= "lo" then
                table.insert(interfaces, iface)
            end
        end
    end

    -- 如果获取接口失败，提供默认接口列表
    if #interfaces == 0 then
        interfaces = {"br-lan", "eth0", "eth1", "wlan0", "wlan1"}
    end

    table.sort(interfaces)

    http.prepare_content("application/json")
    http.write_json(interfaces)
end

-- 检查命令是否存在
local function command_exists(cmd)
    return util.exec("command -v " .. cmd .. " >/dev/null 2>&1 && echo 1 || echo 0"):match("^1")
end

-- 辅助函数：格式化文件大小
local function format_file_size(bytes)
    if not bytes or bytes == 0 then
        return "0 B"
    end
    local sizes = {"B", "KB", "MB", "GB"}
    local i = 1
    local size = bytes
    while size > 1024 and i < #sizes do
        size = size / 1024
        i = i + 1
    end
    return string.format("%.2f %s", size, sizes[i])
end

-- 内部辅助函数：获取 tcpdump 进程的 PID
local function get_tcpdump_pids_for_our_capture()
    local pids = {}
    
    -- 方法1: 使用ps命令获取PID (最精确)
    local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w " .. CAPTURE_FILE .. "' | grep -v 'grep' | awk '{print $1}'")
    if ps_output and ps_output ~= "" then
        for pid in ps_output:gmatch("%d+") do
            table.insert(pids, tonumber(pid))
        end
    end
    
    -- 方法2: 如果第一种方式失败，尝试其他方式
    if #pids == 0 then
        local ps_cmd = "ps w | grep tcpdump | grep -v grep | grep '" .. CAPTURE_FILE .. "'"
        local ps_output = util.exec(ps_cmd)
        if ps_output and ps_output ~= "" then
            -- 使用简单的空格分割并提取PID
            local pid = ps_output:match("^%s*(%d+)")
            if pid then
                table.insert(pids, tonumber(pid))
            end
        end
    end
    
    -- 方法3: 最后尝试直接从/proc目录查找 (最可靠)
    if #pids == 0 and command_exists("ls") then
        local proc_output = util.exec("ls -d /proc/[0-9]* 2>/dev/null")
        if proc_output and proc_output ~= "" then
            for pid_dir in proc_output:gmatch("/proc/(%d+)") do
                local pid = tonumber(pid_dir)
                if pid then
                    -- 尝试读取cmdline文件
                    local cmdline = util.exec("cat /proc/" .. pid .. "/cmdline 2>/dev/null | tr '\\0' ' '")
                    if cmdline and cmdline:match("tcpdump") and cmdline:match(CAPTURE_FILE:gsub("/", "%/%")) then
                        table.insert(pids, pid)
                    end
                end
            end
        end
    end
    
    return pids
end

-- 内部停止函数（仅停止 tcpdump 进程）
local function action_stop_internal()
    -- 尝试使用 killall 停止所有名为 tcpdump 的进程
    if command_exists("killall") then
        util.exec("killall tcpdump 2>/dev/null")
    end
    
    util.exec("sleep 1") -- 增加初始等待时间
    
    -- 添加重试机制，最多尝试3次
    local max_retries = 3
    
    for attempt = 1, max_retries do
        -- 更精确地找到并停止捕获到指定文件的 tcpdump 进程
        local pids_to_kill = get_tcpdump_pids_for_our_capture()
        
        if #pids_to_kill == 0 then
            break -- 所有进程已终止，退出循环
        end
        
        local pids_str = table.concat(pids_to_kill, " ")
        
        if attempt == 1 then
            -- 第一次尝试使用正常终止信号
            util.exec("kill " .. pids_str .. " 2>/dev/null")
            util.exec("sleep 2") -- 增加等待时间确保进程有足够时间终止
        else
            -- 后续尝试使用强制终止信号
            util.exec("kill -9 " .. pids_str .. " 2>/dev/null")
            util.exec("sleep 2") -- 增加SIGKILL后的等待时间
        end
    end
    
    -- 最后再次检查进程状态
    local remaining_pids = get_tcpdump_pids_for_our_capture()
    if #remaining_pids > 0 then
        -- 记录仍然运行的进程
        local remaining_pids_str = table.concat(remaining_pids, ", ")
        util.exec("echo 'Failed to stop tcpdump processes: " .. remaining_pids_str .. "' >> /tmp/tcpdump_stop_errors.log 2>&1")
    end
end

-- 清理抓包文件
local function cleanup_capture_files()
    util.exec("rm -f " .. CAPTURE_FILE .. "* 2>/dev/null")
end

-- 检查抓包状态
function M.action_ajax_status()
    local result = {
        running = false,
        file_exists = false,
        file_size = 0,
        file_size_human = "0 B",
        pid = nil,
        interface = nil
    }

    local status, err = pcall(function()
        -- 检查进程
        local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w " .. CAPTURE_FILE .. "' | head -1")
        if ps_output and ps_output ~= "" then
            local pid = ps_output:match("^%s*(%d+)")
            if pid then
                result.running = true
                result.pid = pid
                local interface = ps_output:match("-i%s+(%S+)")
                if interface then
                    result.interface = interface
                end
            end
        end

        -- 检查主抓包文件
        local stat = nixio.fs.stat(CAPTURE_FILE)
        if stat then
            result.file_exists = true
            result.file_size = stat.size
            result.file_size_human = format_file_size(stat.size)
        end
    end)

    if not status then
        result.error = tostring(err)
        util.exec("logger -t tcpdump_luci 'Status check error: " .. tostring(err) .. "'")
    end

    http.prepare_content("application/json")
    http.write_json(result)
end

-- 过滤器验证（增强版）
local function validate_filter(filter)
    if not filter or filter == "" then
        return true
    end
    
    -- 安全的过滤器验证，不允许 shell 注入
    if filter:match("[;&|$`\\t\\n\\r]") then
        return false
    end
    
    -- 更严格的过滤器字符验证，只允许tcpdump合法的过滤表达式字符
    if not filter:match("^[A-Za-z0-9%s%(%%)=%<%>:_.,%-/%*]+$") then
        return false
    end
    
    -- 检查是否有未闭合的括号
    local open_brackets = select(2, filter:gsub("%(", ""))
    local close_brackets = select(2, filter:gsub("%)", ""))
    if open_brackets ~= close_brackets then
        return false
    end
    
    return true
end

-- 启动抓包
function M.action_start()
    local interface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    local count = http.formvalue("count") or ""
    local duration = http.formvalue("duration") or "" -- 新增：捕获时长限制

    -- 输入验证
    if not interface or interface == "" then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "Please select network interface"})
        return
    end

    if not interface:match("^[A-Za-z0-9%-_%%.]+") then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "Invalid interface name"})
        return
    end

    if not nixio.fs.stat("/sys/class/net/" .. interface) then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "Network interface does not exist"})
        return
    end

    if not validate_filter(filter) then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "Invalid filter format, avoid special characters"})
        return
    end

    -- 验证tcpdump是否安装
    if not command_exists("tcpdump") then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "tcpdump is not installed"})
        return
    end

    -- 停止现有进程并清理文件
    local stop_ok, stop_err = pcall(action_stop_internal)
    if not stop_ok then
        util.exec("logger -t tcpdump_luci 'Failed to stop existing processes: " .. tostring(stop_err) .. "'")
    end
    
    local clean_ok, clean_err = pcall(cleanup_capture_files)
    if not clean_ok then
        util.exec("logger -t tcpdump_luci 'Failed to clean capture files: " .. tostring(clean_err) .. "'")
    end

    -- 构建 tcpdump 命令
    local cmd_parts = {
        "tcpdump",
        "-i", interface,
        "-w", CAPTURE_FILE,
        "-U", -- 实时写入
        "-C", tostring(MAX_CAPTURE_SIZE / 1024 / 1024) -- 文件大小限制 (MB)
    }

    local message_parts = {}

    -- 包数量限制
    if count ~= "" and count:match("^%d+$") then
        local count_num = tonumber(count)
        if count_num and count_num > 0 then
            table.insert(cmd_parts, "-c")
            table.insert(cmd_parts, tostring(count_num))
            table.insert(message_parts, "Stop after " .. count .. " packets")
        end
    end

    -- 捕获时长限制
    if duration ~= "" and duration:match("^%d+$") then
        local duration_num = tonumber(duration)
        if duration_num and duration_num > 0 and duration_num <= MAX_CAPTURE_DURATION then
            table.insert(message_parts, "Stop after " .. duration .. " seconds")
            -- 将在命令中使用timeout包装
            cmd_parts = {"timeout", tostring(duration_num)} .. cmd_parts
        end
    end

    if filter ~= "" then
        table.insert(cmd_parts, filter)
    end

    -- 启动 tcpdump（使用更安全的方式）
    local cmd = table.concat(cmd_parts, " ") .. " 2>/var/log/tcpdump_luci.log &"
    local success = os.execute(cmd)

    util.exec("sleep 1")

    -- 检查是否启动成功
    local pids_after_start = get_tcpdump_pids_for_our_capture()
    success = (#pids_after_start > 0)

    http.prepare_content("application/json")
    if success then
        local message = "TCPDump started successfully"
        if #message_parts > 0 then
            message = message .. " (" .. table.concat(message_parts, "; ") .. ")"
        else
            message = message .. " (manual stop required, file size limit: " .. format_file_size(MAX_CAPTURE_SIZE) .. ")"
        end
        http.write_json({success = true, message = message, pid = pids_after_start[1]})
    else
        http.write_json({
            success = false,
            message = "Failed to start TCPDump, please check interface or filter"
        })
    end
end

-- 停止抓包
function M.action_stop()
    local result = {success = true, message = ""}

    -- 只停止进程，不删除文件
    action_stop_internal()

    local pids_still_running = get_tcpdump_pids_for_our_capture()
    if #pids_still_running > 0 then
        result.success = false
        result.message = "Failed to stop all tcpdump processes, manual intervention may be required (PID: " .. table.concat(pids_still_running, ", ") .. ")"
    else
        result.message = "Capture stopped, file saved for download"
    end

    http.prepare_content("application/json")
    http.write_json(result)
end

-- 下载抓包文件
function M.action_download()
    local stat = nixio.fs.stat(CAPTURE_FILE)

    if not stat then
        http.status(404, "Not Found")
        http.prepare_content("text/plain")
        http.write("Capture file does not exist")
        return
    end

    if stat.size == 0 then
        http.status(400, "Bad Request")
        http.prepare_content("text/plain")
        http.write("Capture file is empty")
        return
    end

    -- 添加文件大小限制检查
    if stat.size > MAX_CAPTURE_SIZE then
        http.status(413, "Payload Too Large")
        http.prepare_content("text/plain")
        http.write("File too large, please capture a smaller packet set")
        return
    end

    local file = io.open(CAPTURE_FILE, "rb")
    if file then
        local content = file:read("*a")
        file:close()

        http.header('Content-Type', 'application/vnd.tcpdump.pcap')
        http.header('Content-Disposition', 'attachment; filename="tcpdump_' .. os.date("%Y%m%d_%H%M%S") .. '.pcap"')
        http.header('Content-Length', tostring(#content))
        http.write(content)
    else
        http.status(500, "Internal Server Error")
        http.write("Failed to read capture file")
    end
end

-- 删除抓包文件
function M.action_delete()
    local result = {success = false, message = "Operation failed"}

    -- 先停止所有相关进程
    local ok, err = pcall(action_stop_internal)
    if not ok then
        util.exec("logger -t tcpdump_luci 'Failed to stop processes: " .. tostring(err) .. "'")
    end

    -- 然后删除文件
    local ok2, err2 = pcall(cleanup_capture_files)
    if not ok2 then
        util.exec("logger -t tcpdump_luci 'Failed to clean files: " .. tostring(err2) .. "'")
    end

    local stat = nixio.fs.stat(CAPTURE_FILE)
    if not stat then
        result.success = true
        result.message = "Capture file deleted"
    else
        result.message = "Failed to delete file"
    end

    http.prepare_content("application/json")
    http.write_json(result)
end

return M
