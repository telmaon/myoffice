#!/bin/bash

echo "=================================================="
echo "    Nezha 深度排查与清理脚本  "
echo "=================================================="
# ----------------------------------------------------
# [0] 排查与清理 恶意 Nezha Agent
# ----------------------------------------------------

echo "=== 开始清理恶意 Nezha Agent ==="

# 1. 查找并停止所有带有随机后缀的 nezha-agent 服务
# 使用正则匹配 nezha-agent-xxx.service 格式，排除正常的 nezha-agent.service
for svc in $(systemctl list-units --type=service --all | grep -Eo 'nezha-agent-[a-zA-Z0-9\-]+\.service'); do
    echo "发现异常服务并正在清除: $svc"
    systemctl stop "$svc"
    systemctl disable "$svc"
    rm -f "/etc/systemd/system/$svc"
    rm -f "/usr/lib/systemd/system/$svc"
done

# 2. 重新加载系统服务守护进程
systemctl daemon-reload

# 3. 清理 /opt/nezha/agent/ 目录下带有随机后缀的配置文件
# 匹配 config-*.yml，这样不会误删你正常的 config.yml
find /opt/nezha/agent/ -name "config-*.yml" -type f -exec rm -f {} +
echo "已清理异常配置文件"

# 4. 强杀可能残留的恶意进程 (针对指定了恶意配置文件的进程)
ps aux | grep 'nezha-agent' | grep 'config-' | awk '{print $2}' | xargs -r kill -9
echo "已清理残留内存进程"

echo "=== 清理完成 ==="
# ----------------------------------------------------
# [1] 排查与清理 SSH 后门公钥
# ----------------------------------------------------
echo "[1/4] 正在排查 SSH 后门公钥..."
AUTH_FILE="/root/.ssh/authorized_keys"

if [ -f "$AUTH_FILE" ]; then
    # 解除可能存在的文件锁定
    chattr -i "$AUTH_FILE" 2>/dev/null
    
    # 1. 自动删除已知的 gary@gary 恶意公钥
    if grep -q "gary@gary" "$AUTH_FILE"; then
        sed -i '/gary@gary/d' "$AUTH_FILE"
        echo "  [+] 已自动删除匹配的恶意公钥 (gary@gary)！"
    fi
    
    # 2. 统计剩余的有效公钥数量 (排除空行和注释行)
    KEY_COUNT=$(grep -v '^\s*$' "$AUTH_FILE" | grep -v '^\s*#' | wc -l)
    
    if [ "$KEY_COUNT" -gt 0 ]; then
        echo -e "\033[31m  [!] 警告：发现 $KEY_COUNT 个 SSH 公钥驻留！\033[0m"
        echo "  请务必人工核对以下公钥是否为你本人所有："
        echo "--------------------------------------------------"
        cat "$AUTH_FILE"
        echo "--------------------------------------------------"
        echo "  如发现未知公钥，请立刻运行: nano $AUTH_FILE 进行删除！"
    else
        echo "  [-] 当前无任何 SSH 公钥存留，安全。"
    fi
else
    echo "  [-] 未找到 $AUTH_FILE 文件，跳过。"
fi


# ----------------------------------------------------
# [2] 排查伪装的 kworker 内存马与 memfd 进程
# ----------------------------------------------------
echo -e "\n[2/4] 正在排查伪装的 kworker 内存马与 memfd 进程..."

# 查杀特征 1：/proc/*/exe 指向 memfd 的异常进程
MEM_PIDS=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep "memfd" | awk -F'/proc/' '{print $2}' | awk -F'/' '{print $1}')
for PID in $MEM_PIDS; do
    echo "  [+] 发现异常 memfd 进程 (PID: $PID)，正在强制结束..."
    kill -9 "$PID" 2>/dev/null
done

# 查杀特征 2：没有中括号的 kworker 进程 (使用 [k] 避免 grep 抓到自己)
FAKE_KWORKERS=$(ps -eo pid,comm,args | grep '[k]worker' | grep -v '\[' | awk '{print $1}')
if [ -n "$FAKE_KWORKERS" ]; then
    for PID in $FAKE_KWORKERS; do
        echo "  [+] 发现伪装的 kworker 进程 (PID: $PID)，正在强制结束..."
        kill -9 "$PID" 2>/dev/null
    done
else
    echo "  [-] 未发现活跃的假 kworker 进程或 memfd 内存马。"
fi


# ----------------------------------------------------
# [3] 排查恶意守护服务 (SystemLoger等)
# ----------------------------------------------------
echo -e "\n[3/4] 正在排查恶意系统服务..."
SYSTEMLOGER_SVC=$(systemctl list-unit-files --type=service 2>/dev/null | grep -i "SystemLoger" | awk '{print $1}')

if [ -n "$SYSTEMLOGER_SVC" ]; then
    echo "  [+] 发现恶意服务 $SYSTEMLOGER_SVC ！正在清理..."
    
    systemctl stop "$SYSTEMLOGER_SVC" 2>/dev/null
    systemctl disable "$SYSTEMLOGER_SVC" 2>/dev/null
    
    for SVC_FILE in $(find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -name "$SYSTEMLOGER_SVC" 2>/dev/null); do
        # 提取并删除二进制文件本体
        BIN_PATH=$(grep "^ExecStart=" "$SVC_FILE" | awk -F'=' '{print $2}' | awk '{print $1}')
        if [ -n "$BIN_PATH" ] && [ -f "$BIN_PATH" ]; then
            chattr -i "$BIN_PATH" 2>/dev/null
            rm -f "$BIN_PATH"
            echo "  [+] 已删除恶意程序本体: $BIN_PATH"
        fi
        
        # 删除服务配置
        chattr -i "$SVC_FILE" 2>/dev/null
        rm -f "$SVC_FILE"
        echo "  [+] 已删除服务配置文件: $SVC_FILE"
    done
    systemctl daemon-reload
else
    echo "  [-] 未发现 SystemLoger 恶意服务。"
fi


# ----------------------------------------------------
# [4] 探测可疑定时任务 (Cron) 关联复活机制
# ----------------------------------------------------
echo -e "\n[4/4] 正在检测可疑的定时任务 (Cron)..."

# 搜索包含已知黑客 IP 段或高危外连命令的任务
SUSPICIOUS_CRON=$(crontab -l 2>/dev/null | grep -E "207\.58\.173\.192|24\.[0-9]+\.|curl|wget|bash")

if [ -n "$SUSPICIOUS_CRON" ]; then
    echo -e "\033[31m  [!] 警告：在当前 root 用户的 crontab 中发现可疑任务！\033[0m"
    echo "--------------------------------------------------"
    echo "$SUSPICIOUS_CRON"
    echo "--------------------------------------------------"
    echo "  请运行 'crontab -e' 仔细核对，如果不是你设置的，请立刻删除！"
else
    echo "  [-] root 用户的 crontab 未见包含已知恶意 IP 或下载命令的异常任务。"
fi

echo "=================================================="
echo "               执行完毕，请注意查收警告信息       "
echo "=================================================="
