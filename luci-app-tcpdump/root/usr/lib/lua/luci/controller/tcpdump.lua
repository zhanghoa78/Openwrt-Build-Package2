module("luci.controller.tcpdump", package.seeall)

function index()
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
function action_interfaces()
    local http = require "luci.http"
    -- 使用 'luci.util' 而不是 'luci.sys'
    local util = require "luci.util" 

    local interfaces = {}
    -- 使用 util.exec，它返回一个字符串
    local list = util.exec("ls /sys/class/net/ 2>/dev/null")

    if list and list ~= "" then
        for iface in list:gmatch("[^\n]+") do
            iface = iface:match("^%s*(.-)%s*$")
            if iface ~= "" and iface ~= "lo" then
                table.insert(interfaces, iface)
            end
        end
    end

    -- 回退逻辑 (如果 ls 失败或 /sys/class/net 为空)
    if #interfaces == 0 then
        interfaces = {"br-lan", "eth0", "eth1", "wlan0", "wlan1"}
    end

    table.sort(interfaces)
    http.prepare_content("application/json")
    http.write_json(interfaces)
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

-- 内部停止函数（仅停止 tcpdump 进程）
local function action_stop_internal()
    local util = require "luci.util"
    
    -- 停止 tcpdump 进程
    util.exec("killall tcpdump 2>/dev/null")
    util.exec("pkill -f 'tcpdump.*-w /tmp/tcpdump.pcap' 2>/dev/null")
    util.exec("sleep 0.5")
    
    local running = util.exec("ps | grep '[t]cpdump '")
    if running and running ~= "" then
        util.exec("killall -9 tcpdump 2>/dev/null")
        util.exec("pkill -9 -f 'tcpdump.*-w /tmp/tcpdump.pcap' 2>/dev/null")
        util.exec("sleep 0.5")
    end
end

-- 清理抓包文件（只删文件）
local function cleanup_capture_files()
    local util = require "luci.util"
    util.exec("rm -f /tmp/tcpdump.pcap* 2>/dev/null")
end

-- 检查抓包状态 (纯只读)
function action_ajax_status()
    local util = require "luci.util"
    local nixio = require "nixio"
    local http = require "luci.http"
    
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
        local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w /tmp/tcpdump.pcap' | head -1")
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
        local file = "/tmp/tcpdump.pcap"
        local stat = nixio.fs.stat(file)
        if stat then
            result.file_exists = true
            result.file_size = stat.size
            result.file_size_human = format_file_size(stat.size)
        end
    end)
    
    if not status then
        result.error = tostring(err)
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end

-- 过滤器验证
local function validate_filter(filter)
    if not filter or filter == "" then
        return true
    end
    if filter:match("[;&|$`]") then
        return false
    end
    return filter:match("^[%w%s%|&!%=%>%<%(%):%/%-%*%.%[%]',]+$") ~= nil
end

-- 启动抓包 (已移除文件大小限制)
function action_start()
    local http = require "luci.http"
    local util = require "luci.util"
    local nixio = require "nixio"
    
    local interface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    -- local filesize = http.formvalue("filesize") or "" -- 已移除
    local count = http.formvalue("count") or ""
    
    -- 输入验证
    if not interface or interface == "" then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "请选择网络接口"})
        return
    end
    
    if not interface:match("^[%w%-_%.]+$") then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "无效的接口名称"})
        return
    end
    
    if not nixio.fs.stat("/sys/class/net/" .. interface) then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "网络接口不存在"})
        return
    end
    
    if not validate_filter(filter) then
        http.prepare_content("application/json")
        http.write_json({success = false, message = "无效的过滤器格式"})
        return
    end
    
    -- 停止现有进程并清理文件
    action_stop_internal()
    cleanup_capture_files()
    
    -- 构建 tcpdump 命令
    local cmd_parts = {
        "tcpdump",
        "-i", interface,
        "-w", "/tmp/tcpdump.pcap",
        "-U"
    }
    
    local message_parts = {}

    -- 1. 包数量限制 (tcpdump 原生支持)
    if count ~= "" and count:match("^%d+$") then
        local count_num = tonumber(count)
        if count_num and count_num > 0 then
            table.insert(cmd_parts, "-c")
            table.insert(cmd_parts, tostring(count_num))
            table.insert(message_parts, "捕获 " .. count .. " 个包后停止")
        end
    end
    
    -- 2. 文件大小限制 (已移除)
    
    if filter ~= "" then
        table.insert(cmd_parts, filter)
    end
    
    -- 启动 tcpdump
    local cmd = table.concat(cmd_parts, " ") .. " 2>/dev/null &"
    os.execute(cmd)
    
    util.exec("sleep 1")
    
    -- 检查是否启动成功并获取 PID
    local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w /tmp/tcpdump.pcap' | head -1")
    local pid = nil
    if ps_output and ps_output ~= "" then
        pid = ps_output:match("^%s*(%d+)")
    end

    local success = (pid ~= nil)
    
    http.prepare_content("application/json")
    if success then
        local message = "TCPDump 启动成功"
        if #message_parts > 0 then
            message = message .. " (" .. table.concat(message_parts, "；") .. ")"
        else
            message = message .. " (请手动停止)"
        end
        http.write_json({success = true, message = message})
    else
        local error_detail = ""
        if not util.exec("which tcpdump") then
             error_detail = "tcpdump 未安装"
        else
             error_detail = "进程启动失败，请检查接口或过滤器"
        end
        http.write_json({
            success = false, 
            message = "TCPDump 启动失败: " .. error_detail
        })
    end
end

-- 停止抓包（只停止进程，保留文件）
function action_stop()
    local http = require "luci.http"
    local util = require "luci.util"
    
    local result = {success = true, message = ""}
    
    -- 只停止进程，不删除文件
    action_stop_internal()
    
    local running = util.exec("ps | grep '[t]cpdump '")
    if running and running ~= "" then
        result.success = false
        result.message = "无法停止 tcpdump 进程"
    else
        result.message = "抓包已停止，文件已保存可供下载"
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end

-- 下载抓包文件
function action_download()
    local http = require "luci.http"
    local nixio = require "nixio"
    
    local file_path = "/tmp/tcpdump.pcap"
    local stat = nixio.fs.stat(file_path)
    
    if not stat then
        http.status(404, "Not Found")
        http.prepare_content("text/plain")
        http.write("抓包文件不存在")
        return
    end
    
    if stat.size == 0 then
        http.status(400, "Bad Request")
        http.prepare_content("text/plain")
        http.write("抓包文件为空")
        return
    end
    
    local file = io.open(file_path, "rb")
    if file then
        local content = file:read("*a")
        file:close()
        
        http.header('Content-Type', 'application/vnd.tcpdump.pcap')
        http.header('Content-Disposition', 'attachment; filename="tcpdump_' .. os.date("%Y%m%d_%H%M%S") .. '.pcap"')
        http.header('Content-Length', tostring(#content))
        http.write(content)
    else
        http.status(500, "Internal Server Error")
        http.write("无法读取抓包文件")
    end
end

-- 删除抓包文件（只有用户明确点击删除时才删除）
function action_delete()
    local nixio = require "nixio"
    local http = require "luci.http"
    local util = require "luci.util"
    
    local result = {success = false, message = "操作失败"}
    
    -- 先停止所有相关进程
    action_stop_internal()
    
    -- 然后删除文件
    cleanup_capture_files()
    
    local stat = nixio.fs.stat("/tmp/tcpdump.pcap")
    if not stat then
        result.success = true
        result.message = "抓包文件已删除"
    else
        result.message = "无法删除文件"
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end
