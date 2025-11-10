-- tcpdump.lua - 版本 2.2: 稳定、健壮且易于维护的 LuCI tcpdump 控制器。
-- 本版本将 ebtables 管理逻辑作为内嵌模块集成，实现了单文件部署的便利性，
-- 同时通过逻辑分区保持了代码的结构化和清晰度。

module("luci.controller.admin.services.tcpdump", package.seeall)

-- 引入所有必要的 LuCI 和 Nixio 库
local sys = require "luci.sys"
local http = require "luci.http"
local util = require "luci.util"
local fs = require "nixio.fs"

-- ========================== 配置常量 ========================== --
-- 定义抓包文件的存储路径
local PCAP_FILE = "/tmp/tcpdump.pcap"
-- 定义一个唯一的进程签名，用于在进程列表中准确地找到我们的 tcpdump 实例。
-- 这是识别进程最可靠的方式，避免了使用 PID 文件可能带来的问题。
local PROCESS_SIGNATURE = "tcpdump -w " .. PCAP_FILE
-- ============================================================= --


-- ========================================================================= --
-- [内嵌模块] EBTABLES 管理器                                                --
-- ------------------------------------------------------------------------- --
-- 将所有 ebtables 相关的操作封装在这个局部表 (table) 中。                   --
-- 这样做可以实现逻辑上的分离，使得代码更整洁、更易于维护。                  --
-- ========================================================================= --
local EbtablesManager = {}

do -- 使用 do...end 块创建一个独立的作用域，防止内部变量污染外部环境
    
    -- 定义需要管理的 ebtables 规则集。
    -- 将规则集中定义在这里，未来修改或增加规则时，只需改动此处。
    local EBTABLES_RULES = {
        -- 规则 1: 豁免 IPTV 组播流量。
        -- 对于目的地址为 224.0.0.0/4 (IPv4 组播地址范围) 的 UDP 报文，直接 ACCEPT，
        -- 不将其重定向到 CPU，从而保证 IPTV 等服务的正常运行。
        "ebtables -t broute -A BROUTING -p ipv4 --ip-proto udp --ip-dst 224.0.0.0/4 -j ACCEPT",
        
        -- 规则 2: 重定向所有其他流量以进行捕获。
        -- 将所有通过网桥的二层流量重定向到三层协议栈 (redirect)，并指定 DROP 目标。
        -- 这会强制内核处理这些报文，从而让 tcpdump 能够捕获到它们。
        "ebtables -t broute -A BROUTING -j redirect --redirect-target DROP"
    }

    -- "私有"函数：清空 BROUTING 链。
    -- 在添加新规则之前调用此函数，可以确保链是干净的，避免规则重复或冲突。
    local function clear_brouting_chain()
        -- -F 参数表示 flush (清空) 指定的链。错误输出重定向到 /dev/null 以保持静默。
        sys.call("ebtables -t broute -F BROUTING >/dev/null 2>&1")
    end

    ---
    -- 检查我们的 brouting 规则是否处于激活状态。
    -- @return boolean: 如果规则已激活，返回 true，否则返回 false。
    ---
    function EbtablesManager.is_active()
        -- 通过检查关键的 'redirect' 规则是否存在来判断功能是否开启。
        -- `grep -q` 参数使其在找到匹配项后立即以成功状态 (0) 退出，且不产生任何输出，效率很高。
        local check_cmd = "ebtables -t broute -L BROUTING | grep -- '-j redirect --redirect-target DROP' -q"
        return (sys.call(check_cmd) == 0)
    end

    ---
    -- 激活 brouting 规则集。
    -- 该操作是幂等的：多次调用会得到相同的结果。
    ---
    function EbtablesManager.start()
        clear_brouting_chain() -- 先清空，确保状态一致
        for _, rule in ipairs(EBTABLES_RULES) do
            sys.call(rule) -- 依次添加规则列表中的所有规则
        end
        return true
    end

    ---
    -- 停用 brouting 规则集。
    -- 通过清空整个链来达到停用效果，简单可靠。
    ---
    function EbtablesManager.stop()
        clear_brouting_chain()
        return true
    end
end
-- ===================== EBTABLES 管理器模块结束 ====================== --


-- LuCI 菜单和页面入口点定义
function index()
    -- 定义在 "服务" 菜单下的 "TCPDump" 条目
    entry({"admin", "services", "tcpdump"}, view("admin_services/tcpdump"), _("TCPDump"), 70).dependent = true
    
    -- 定义所有后端 API 的入口点，供前端 JavaScript 调用
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_interfaces")) -- 获取网络接口列表
    entry({"admin", "services", "tcpdump", "status"}, call("action_status"))       -- 获取当前状态
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))         -- 开始抓包
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))           -- 停止抓包
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))   -- 下载抓包文件
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))       -- 删除抓包文件
    entry({"admin", "services", "tcpdump", "broute"}, call("action_broute"))       -- 开关二层桥接捕获
end

---
-- 通过扫描系统进程列表来获取 tcpdump 的进程 ID (PID)。
-- 这是比依赖 PID 文件更可靠的方法。
-- @return string or nil: 如果找到进程，返回 PID 字符串；否则返回 nil。
---
local function get_pid_by_signature()
    -- 命令解析:
    -- 1. `ps w`: 列出所有进程，并显示完整命令 (w 参数防止长命令被截断)。
    -- 2. `grep '%s'`: 查找包含我们唯一签名 (PROCESS_SIGNATURE) 的行。
    -- 3. `grep -v 'grep'`: 排除 grep 命令自身，防止误判。
    -- 4. `awk '{print $1}'`: 提取第一列，即进程的 PID。
    local cmd = string.format("ps w | grep '%s' | grep -v 'grep' | awk '{print $1}'", PROCESS_SIGNATURE)
    local pid = util.trim(sys.exec(cmd)) -- 执行命令并去除结果中的首尾空格
    
    -- 确保返回的是一个有效的数字 PID
    if pid and tonumber(pid) then
        return pid
    end
    return nil
end

-- 辅助函数：以 JSON 格式向前端返回数据
local function json_response(data)
    http.prepare_content("application/json")
    http.write_json(data)
end

-- API: 获取系统所有网络接口的列表
function action_interfaces()
    local interfaces = {}
    for _, dev in ipairs(sys.net.get_interfaces()) do
        table.insert(interfaces, dev:name())
    end
    json_response(interfaces)
end

-- API: 获取 tcpdump 的当前运行状态
function action_status()
    local pid = get_pid_by_signature()
    local file_stat = fs.stat(PCAP_FILE)
    local ebtables_installed = sys.pkg.is_installed("ebtables")
    
    -- [集成] 使用内嵌的 EbtablesManager 来获取二层捕获的状态
    local broute_enabled = ebtables_installed and EbtablesManager.is_active()
    
    json_response({
        running = (pid ~= nil), -- 进程是否在运行
        pid = pid, -- 进程 PID
        file_exists = (file_stat ~= nil), -- pcap 文件是否存在
        file_size = file_stat and file_stat.size or 0, -- pcap 文件大小
        ebtables_installed = ebtables_installed, -- ebtables 是否已安装
        broute_enabled = broute_enabled, -- 二层桥接捕获是否已开启
    })
end

-- API: 启动 tcpdump 抓包
function action_start()
    -- 检查是否已有实例在运行
    if get_pid_by_signature() then
        return json_response({ success = false, message = "抓包已在运行中。" })
    end

    -- 从前端获取参数
    local iface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    local filesize_mb = tonumber(http.formvalue("filesize"))
    local count = tonumber(http.formvalue("count"))

    -- [安全校验] 必须对用户输入进行严格校验，防止命令注入
    -- 1. 校验接口名称是否合法
    local valid_iface = false
    if iface then
        for _, dev in ipairs(sys.net.get_interfaces()) do
            if dev:name() == iface then
                valid_iface = true
                break
            end
        end
    end
    if not valid_iface then
        return json_response({ success = false, message = "错误：无效的网络接口。" })
    end
    -- 2. 校验过滤器是否包含危险字符 (基本防护)
    if filter:match("[;&|`$()]") then
        return json_response({ success = false, message = "错误：过滤器包含禁用字符。" })
    end

    -- 构建 tcpdump 命令
    local cmd_parts = {"tcpdump", "-i", iface, "-w", PCAP_FILE}
    if filesize_mb and filesize_mb > 0 then
        table.insert(cmd_parts, "-C")
        table.insert(cmd_parts, tostring(math.floor(filesize_mb)))
        table.insert(cmd_parts, "-W")
        table.insert(cmd_parts, "1") -- 只保留一个滚动文件
    end
    if count and count > 0 then
        table.insert(cmd_parts, "-c")
        table.insert(cmd_parts, tostring(math.floor(count)))
    end

    -- 拼接最终命令字符串，并对过滤器内容进行转义，增加安全性
    local full_cmd_str
    if filter and #filter > 0 then
        full_cmd_str = table.concat(cmd_parts, " ") .. " " .. "'" .. filter:gsub("'", "'\\''") .. "'"
    else
        full_cmd_str = table.concat(cmd_parts, " ")
    end
    
    -- 在后台执行命令，并将标准输出和错误输出重定向到 /dev/null
    sys.call(full_cmd_str .. " >/dev/null 2>&1 &")
    
    -- 短暂等待，然后验证进程是否已成功启动
    util.nanosleep(500 * 1000 * 1000) -- 暂停 500 毫秒
    if get_pid_by_signature() then
        json_response({ success = true, message = "抓包已成功启动。" })
    else
        json_response({ success = false, message = "启动抓包失败，请检查参数或系统日志。" })
    end
end

-- API: 停止 tcpdump 抓包
function action_stop()
    local pid = get_pid_by_signature()
    if pid then
        sys.call("kill " .. pid)
    end
    
    -- [集成] 停止抓包时，总是调用管理器来清理 ebtables 规则，确保系统恢复干净状态。
    EbtablesManager.stop()
    
    -- 短暂等待，然后验证进程是否已成功停止
    util.nanosleep(500 * 1000 * 1000)
    if not get_pid_by_signature() then
        json_response({ success = true, message = "抓包已成功停止。" })
    else
        json_response({ success = false, message = "停止进程失败，可能需要手动干预。" })
    end
end

-- API: 下载抓包文件
function action_download()
    if fs.access(PCAP_FILE) then
        http.prepare_content("application/vnd.tcpdump.pcap")
        http.set_header("Content-Disposition", "attachment; filename=\"tcpdump.pcap\"")
        http.write_file(PCAP_FILE)
    else
        http.status(404, "Not Found")
        http.write("文件未找到。")
    end
end

-- API: 删除抓包文件
function action_delete()
    if fs.access(PCAP_FILE) then
        fs.unlink(PCAP_FILE)
        json_response({ success = true, message = "文件已成功删除。" })
    else
        json_response({ success = false, message = "文件不存在或已被删除。" })
    end
end

-- API: 开启或关闭二层桥接流量捕获
function action_broute()
    if not sys.pkg.is_installed("ebtables") then
        return json_response({ success = false, message = "错误：ebtables 未安装。" })
    end

    local enable = http.formvalue("enable") == "true"
    
    if enable then
        -- [集成] 调用内嵌管理器的 start 函数来应用规则
        EbtablesManager.start()
        
        -- 操作后进行验证，确保成功
        if EbtablesManager.is_active() then
            json_response({ success = true, message = "高级二层捕获规则已成功开启。" })
        else
            json_response({ success = false, message = "开启规则失败，请检查系统日志。" })
        end
    else
        -- [集成] 调用内嵌管理器的 stop 函数来清理规则
        EbtablesManager.stop()
        json_response({ success = true, message = "高级二层捕获规则已关闭。" })
    end
end
