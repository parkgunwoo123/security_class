#Security Shell 취합중 (최종)
#!/bin/bash

### 헤더 출력 ###
cat Team_png.txt
echo "점검 장치"
echo "$(uname -a)"
echo "점검자 : password1234"

LOGFILE="security_audit.log"
FAILLOG="security_audit_fail.log"
echo "[Security Audit Interactive - $(date)]" > "$LOGFILE"
echo "[Security Audit FAIL Log - $(date)]" > "$FAILLOG"

# 결과 출력 함수 (FAIL 로그에 이유 포함)
function print_result {
    local id="$1"
    local desc="$2"
    local status="$3"
    local reason="$4"

    if [ "$status" -eq 0 ]; then
        echo "[✅]$id $desc ...OK" | tee -a "$LOGFILE"
    else
        echo "[❌]$id $desc ...FAIL" | tee -a "$LOGFILE"
        echo "[❌]$id $desc ...FAIL: $reason" >> "$FAILLOG"
    fi
}

########################################
# U-01 root 계정 원격접속 차단
########################################
function audit_1 {
    sshfile="/etc/ssh/sshd_config"
    telnetfile="/etc/pam.d/login"
    status=0
    reason=""

    if grep -q "PermitRootLogin yes" "$sshfile" 2>/dev/null; then
        status=1
        reason+="SSH PermitRootLogin yes; "
    fi
    if ! grep -q "pam_securetty.so" "$telnetfile" 2>/dev/null; then
        status=1
        reason+="Telnet pam_securetty.so 미설정; "
    fi

    print_result "U-01" "root 계정 원격접속 차단" "$status" "$reason"
}

########################################
# U-02 패스워드 복잡성 설정
########################################
function audit_2 {
    file="/etc/pam.d/system-auth"
    words=("retry=3" "minlen=8" "lcredit=-1" "ucredit=-1" "dcredit=-1" "ocredit=-1")
    status=0
    reason=""

    for w in "${words[@]}"; do
        if ! grep -q "$w" "$file" 2>/dev/null; then
            status=1
            reason+="$w 미설정; "
        fi
    done

    print_result "U-02" "패스워드 복잡성 설정" "$status" "$reason"
}

########################################
# U-03 계정 잠금 임계값 설정
########################################
function audit_3 {
    file="/etc/pam.d/system-auth"
    status=0
    reason=""

    if ! grep -q "pam_tally.so" "$file" 2>/dev/null; then
        status=1
        reason+="pam_tally.so 없음; "
    fi
    for w in "deny=5" "unlock_time=120" "no_magic_root"; do
        if ! grep -q "$w" "$file" 2>/dev/null; then
            status=1
            reason+="$w 미설정; "
        fi
    done
    print_result "U-03" "계정 잠금 임계값 설정" "$status" "$reason"
}

########################################
# U-04 패스워드 암호화 파일 점검
########################################
function audit_4 {
    passwd_file="/etc/passwd"
    shadow_file="/etc/shadow"
    status=0
    reason=""

    if [ ! -f "$shadow_file" ]; then
        status=1
        reason+="/etc/shadow 파일 없음; "
    fi
    root_line=$(grep "^root:" "$passwd_file")
    if [[ "$root_line" != *":x:"* ]]; then
        status=1
        reason+="root 패스워드 암호화되지 않음; "
    fi

    print_result "U-04" "패스워드 암호화 파일 점검" "$status" "$reason"
}

########################################
# U-44 root 이외 UID=0 계정 점검
########################################
function audit_44 {
    result=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)
    status=0
    reason=""
    [ -n "$result" ] && { status=1; reason+="root 외 UID=0 계정 존재: $result; "; }

    print_result "U-44" "root 이외 UID=0 계정 점검" "$status" "$reason"
}

########################################
# U-45 root 계정 su 제한 점검
########################################
function audit_45 {
    PAM_FILE="/etc/pam.d/su"
    status=0
    reason=""
    if ! grep -q "pam_wheel.so" "$PAM_FILE" 2>/dev/null; then
        status=1
        reason+="pam_wheel.so 미설정; "
    fi

    print_result "U-45" "root 계정 su 제한 점검" "$status" "$reason"
}

########################################
# U-46 패스워드 최소 길이
########################################
function audit_46 {
    file="/etc/login.defs"
    status=0
    reason=""
    if ! grep -q "PASS_MIN_LEN" "$file" 2>/dev/null; then
        status=1
        reason+="PASS_MIN_LEN 미설정; "
    elif ! grep -q "PASS_MIN_LEN.*8" "$file" 2>/dev/null; then
        status=1
        reason+="PASS_MIN_LEN 8 미설정; "
    fi
    print_result "U-46" "패스워드 최소 길이 설정" "$status" "$reason"
}

########################################
# U-47 패스워드 최대 사용기간
########################################
function audit_47 {
    file="/etc/login.defs"
    status=0
    reason=""
    if ! grep -q "PASS_MAX_DAYS.*90" "$file" 2>/dev/null; then
        status=1
        reason+="PASS_MAX_DAYS 90 미설정; "
    fi
    print_result "U-47" "패스워드 최대 사용기간 설정" "$status" "$reason"
}

########################################
# U-48 패스워드 최소 사용기간
########################################
function audit_48 {
    file="/etc/login.defs"
    status=0
    reason=""
    if ! grep -q "PASS_MIN_DAYS.*1" "$file" 2>/dev/null; then
        status=1
        reason+="PASS_MIN_DAYS 1 미설정; "
    fi
    print_result "U-48" "패스워드 최소 사용기간 설정" "$status" "$reason"
}

########################################
# U-49 불필요한 기본 계정 점검
########################################
function audit_49 {
    status=0
    reason=""
    bad_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(nologin|false)/){print $1}' /etc/passwd)
    if [ -n "$bad_accounts" ]; then
        status=1
        reason+="불필요 계정 존재: $bad_accounts; "
    fi
    print_result "U-49" "불필요한 기본 계정 점검" "$status" "$reason"
}

########################################
# U-50 관리자 그룹 점검
########################################
function audit_50 {
    status=0
    reason=""
    if ! grep -Eq "^root:x:0:root$|^root:x:0:$" /etc/group; then
        status=1
        reason+="관리자 그룹 이상; "
    fi
    print_result "U-50" "관리자 그룹 점검" "$status" "$reason"
}

########################################
# U-51 불필요한 그룹 점검
########################################
function audit_51 {
    status=0
    reason=""
    while IFS=: read -r group_name _ gid _; do
        if ! awk -F: -v gid="$gid" '$4==gid {found=1} END{exit !found}' /etc/passwd; then
            status=1
            reason+="불필요 그룹: $group_name; "
        fi
    done < /etc/group
    print_result "U-51" "불필요한 그룹 점검" "$status" "$reason"
}

########################################
# U-52 동일한 UID 점검
########################################
function audit_52 {
    status=0
    reason=""
    duplicates=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [ -n "$duplicates" ]; then
        status=1
        reason+="중복 UID: $duplicates; "
    fi
    print_result "U-52" "동일한 UID 점검" "$status" "$reason"
}

########################################
# U-53 불필요 계정 로그인 제한
########################################
function audit_53 {
    status=0
    reason=""
    bad_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(nologin|false)/){print $1}' /etc/passwd)
    if [ -n "$bad_accounts" ]; then
        status=1
        reason+="로그인 제한 안된 계정: $bad_accounts; "
    fi
    print_result "U-53" "불필요 계정 로그인 제한" "$status" "$reason"
}

########################################
# U-54 Session Timeout 설정
########################################
function audit_54 {
    status=0
    reason=""
    if grep -q "TMOUT" /etc/profile 2>/dev/null; then
        tmout_val=$(grep "TMOUT" /etc/profile | awk -F'=' '{print $2}' | tail -n1)
        if [ "$tmout_val" -gt 600 ]; then
            status=1
            reason+="TMOUT 값 $tmout_val 초 → 600 초 초과; "
        fi
    else
        status=1
        reason+="TMOUT 미설정; "
    fi
    print_result "U-54" "Session Timeout 설정" "$status" "$reason"
}

########################################
# U-42 패치관리 (샘플)
########################################
function audit_42 {
    status=1
    reason="보안 패키지 최신 버전 설치 필요"
    print_result "U-42" "패치관리" "$status" "$reason"
}

########################################
# U-43 로그 분석
########################################
function audit_43 {
    status=0
    reason=""

    FAILED_LOGINS=$(lastb 2>/dev/null | wc -l)
    if [ "$FAILED_LOGINS" -gt 0 ]; then
        status=1
        reason+="실패한 로그인 이력 발견 ($FAILED_LOGINS 건); "
    fi

    if [ -f /var/log/sulog ]; then
        SUSPICIOUS_SU=$(grep -v "root to root" /var/log/sulog | wc -l)
        if [ "$SUSPICIOUS_SU" -gt 0 ]; then
            status=1
            reason+="비인가 su 사용 이력 발견 ($SUSPICIOUS_SU 건); "
        fi
    else
        reason+="sulog 파일 없음; "
    fi

    if [ -f /var/log/xferlog ]; then
        FTP_ACCESS=$(grep -i "ftp" /var/log/xferlog | wc -l)
        if [ "$FTP_ACCESS" -gt 0 ]; then
            status=1
            reason+="FTP 접근 로그 발견 ($FTP_ACCESS 건); "
        fi
    else
        reason+="xferlog 파일 없음; "
    fi

    print_result "U-43" "로그 분석 결과" "$status" "$reason"
}

########################################
# U-72 로그 설정 점검
########################################
function audit_72 {
    TARGET_FILE="/etc/rsyslog.conf"
    status=0
    reason=""

    declare -A CHECKS
    CHECKS["*.info;mail.none;authpriv.none;cron.none"]="/var/log/messages"
    CHECKS["authpriv.*"]="/var/log/secure"
    CHECKS["mail.*"]="/var/log/maillog"
    CHECKS["cron.*"]="/var/log/cron"
    CHECKS["*.alert"]="/dev/console"
    CHECKS["*.emerg"]="*"

    for KEY1 in "${!CHECKS[@]}"; do
        KEY2=${CHECKS[$KEY1]}
        if ! grep -q "$KEY1" "$TARGET_FILE"; then
            status=1
            reason+="$KEY1 없음; "
        else
            if ! grep "$KEY1" "$TARGET_FILE" | grep -q "$KEY2"; then
                status=1
                reason+="$KEY1 발견 → 하지만 $KEY2 없음; "
            fi
        fi
    done

    print_result "U-72" "시스템 로깅 설정 점검" "$status" "$reason"
}


###########################################################
#########################승환님 파트####################
###########################################################
########################################
# U-19 finger 서비스 비활성화
########################################
function audit_19 {
    status=0; reason=""
    rpm -q finger &>/dev/null && reason+="finger 패키지 설치됨; "
    pgrep -x fingerd &>/dev/null && status=1 && reason+="finger 데몬 실행 중; "
    ss -ltn | grep -q ":79 " && status=1 && reason+="finger 포트(79) 열림; "
    print_result "U-19" "finger 서비스 비활성화" "$status" "$reason"
}

########################################
# U-20 Anonymous FTP 비활성화
########################################
function audit_20 {
    status=0; reason=""
    if rpm -q vsftpd &>/dev/null; then
        grep -q "^anonymous_enable=NO" /etc/vsftpd/vsftpd.conf || status=1 && reason+="anonymous_enable 설정 미흡; "
    fi
    print_result "U-20" "Anonymous FTP 비활성화" "$status" "$reason"
}

########################################
# U-21 r 계열 서비스 비활성화
########################################
function audit_21 {
    status=0; reason=""
    for svc in rsh rlogin rexec; do
        systemctl is-enabled ${svc}.service &>/dev/null && status=1 && reason+="$svc 활성화됨; "
    done
    print_result "U-21" "r 계열 서비스 비활성화" "$status" "$reason"
}

########################################
# U-22 cron 파일 소유자 및 권한설정
########################################
function audit_22 {
    status=0; reason=""
    find /etc/cron* -type f ! -perm 600 | grep -q . && status=1 && reason+="cron 파일 권한 취약; "
    print_result "U-22" "cron 파일 소유자 및 권한설정" "$status" "$reason"
}

########################################
# U-23 Dos 공격에 취약한 서비스 비활성화
########################################
function audit_23 {
    status=0; reason=""
    grep -q "^net.ipv4.tcp_syncookies=1" /etc/sysctl.conf || status=1 && reason+="tcp_syncookies 미설정; "
    print_result "U-23" "Dos 공격에 취약한 서비스 비활성화" "$status" "$reason"
}

########################################
# U-24 NFS 서비스 비활성화
########################################
function audit_24 {
    status=0; reason=""
    systemctl is-enabled nfs-server.service &>/dev/null && status=1 && reason+="nfs-server 활성화됨; "
    print_result "U-24" "NFS 서비스 비활성화" "$status" "$reason"
}

########################################
# U-25 NFS 접근 통제
########################################
function audit_25 {
    status=0; reason=""
    if [ -f /etc/exports ]; then
        if grep -q "^\*" /etc/exports; then
            status=1
            reason+="exports 전체 오픈 설정 확인; "
        fi
    else
        reason+="exports 파일 없음; "
        status=0  # NFS 안쓰면 FAIL 아니고 OK로 처리
    fi
    print_result "U-25" "NFS 접근 통제" "$status" "$reason"
}


########################################
# U-26 automountd 제거
########################################
function audit_26 {
    status=0; reason=""
    systemctl is-enabled autofs.service &>/dev/null && status=1 && reason+="automountd 활성화됨; "
    print_result "U-26" "automountd 제거" "$status" "$reason"
}

########################################
# U-27 RPC 서비스 확인
########################################
function audit_27 {
    status=0; reason=""
    rpcinfo -p &>/dev/null && status=1 && reason+="RPC 서비스 활성화됨; "
    print_result "U-27" "RPC 서비스 확인" "$status" "$reason"
}

########################################
# U-28 NIS, NIS+ 점검
########################################
function audit_28 {
    status=0; reason=""
    for svc in nis ypbind; do
        systemctl is-enabled ${svc}.service &>/dev/null && status=1 && reason+="$svc 활성화됨; "
    done
    print_result "U-28" "NIS, NIS+ 점검" "$status" "$reason"
}

########################################
# U-29 tftp, talk 서비스 비활성화
########################################
function audit_29 {
    status=0; reason=""
    for svc in tftp talk; do
        systemctl is-enabled ${svc}.service &>/dev/null && status=1 && reason+="$svc 활성화됨; "
    done
    print_result "U-29" "tftp, talk 서비스 비활성화" "$status" "$reason"
}

########################################
# U-30 Sendmail 버전 점검
########################################
function audit_30 {
    status=0; reason=""
    if rpm -q sendmail &>/dev/null; then
        version=$(rpm -q --queryformat '%{VERSION}' sendmail)
        reason+="sendmail 버전: $version; "
    else
        reason+="sendmail 미설치; "
    fi
    print_result "U-30" "Sendmail 버전 점검" "$status" "$reason"
}

########################################
# U-31 스팸 메일 릴레이 제한
########################################
function audit_31 {
    status=0; reason=""
    if rpm -q sendmail &>/dev/null; then
        grep -q "AccessDeniedMatchList" /etc/mail/sendmail.mc || status=1 && reason+="릴레이 제한 설정 없음; "
    else
        reason+="sendmail 미설치; "
        status=0  # sendmail 없으면 실패 아님, OK 처리
    fi
    print_result "U-31" "스팸 메일 릴레이 제한" "$status" "$reason"
}

########################################
# U-32 일반 사용자의 Sendmail 실행 방지
########################################
function audit_32 {
    status=0; reason=""
    ls -l /usr/sbin/sendmail | grep -q root && reason+="sendmail 소유 root; " || status=1 && reason+="권한/소유 이상; "
    print_result "U-32" "일반 사용자의 Sendmail 실행 방지" "$status" "$reason"
}

########################################
# U-33 DNS 보안 버전 패치
########################################
function audit_33 {
    status=0; reason=""
    if rpm -q bind &>/dev/null; then
        reason+="BIND 설치됨; "
    else
        reason+="BIND 미설치; "
        status=1
    fi
    print_result "U-33" "DNS 보안 버전 패치" "$status" "$reason"
}

########################################
# U-34 DNS Zone Transfer 설정
########################################
function audit_34 {
    status=0; reason=""
    if [ -f /etc/named.conf ]; then
        grep -q "allow-transfer" /etc/named.conf || status=1 && reason+="zone transfer 제한 설정 없음; "
    else
        reason+="named.conf 파일 없음; "
        status=1
    fi
    print_result "U-34" "DNS Zone Transfer 설정" "$status" "$reason"
}

########################################
# U-35 웹서비스 디렉토리 리스팅 제거
########################################
function audit_35 {
    status=0; reason=""
    if [ -f /etc/httpd/conf/httpd.conf ]; then
        grep -q -E "autoindex on" /etc/httpd/conf/httpd.conf && status=1 && reason+="디렉토리 리스팅 활성화됨; "
    else
        reason+="httpd.conf 파일 없음; "
        status=1
    fi
    print_result "U-35" "웹서비스 디렉토리 리스팅 제거" "$status" "$reason"
}
########################################
# U-36 웹서비스 웹 프로세스 권한 제한
########################################
function audit_36 {
    status=0; reason=""
    user=$(ps -eo user,comm | grep -E 'httpd|apache2' | grep -v root | awk '{print $1}' | sort | uniq)

    if [ -z "$user" ]; then
        reason="Apache 프로세스 미실행; "
        status=0
    elif [[ "$user" =~ ^(nobody|apache|www-data)$ ]]; then
        status=0
        reason="적절한 권한($user)으로 실행 중; "
    else
        status=1
        reason="웹서비스가 일반 사용자($user) 권한으로 실행 중; "
    fi
    print_result "U-36" "웹서비스 웹 프로세스 권한 제한" "$status" "$reason"
}

########################################
# U-37 웹서비스 상위 디렉터리 접근 금지
########################################
function audit_37 {
    status=0; reason=""
    if grep -q -i "Options.*Indexes" /etc/httpd/conf/httpd.conf; then
        status=1
        reason+="Indexes 옵션 사용 → 상위 디렉터리 리스트 노출 우려; "
    fi
    print_result "U-37" "웹서비스 상위 디렉터리 접근 금지" "$status" "$reason"
}

########################################
# U-38 웹서비스 불필요한 파일 제거
########################################
function audit_38 {
    status=0; reason=""
    http_root=$(grep -i "^DocumentRoot" /etc/httpd/conf/httpd.conf | awk '{print $2}' | sed 's/"//g')
    [ -z "$http_root" ] && http_root="/var/www/html"

    for file in "manual" "cgi-bin" "test" "example"; do
        if [ -e "$http_root/$file" ]; then
            status=1
            reason+="$file 존재; "
        fi
    done
    print_result "U-38" "웹서비스 불필요한 파일 제거" "$status" "$reason"
}

########################################
# U-39 웹서비스 링크 사용 금지
########################################
function audit_39 {
    status=0; reason=""
    if grep -i "Options.*FollowSymLinks" /etc/httpd/conf/httpd.conf; then
        status=1
        reason+="FollowSymLinks 설정 있음; "
    fi
    print_result "U-39" "웹서비스 링크 사용 금지" "$status" "$reason"
}

########################################
# U-40 웹서비스 업로드 및 다운로드 제한
########################################
function audit_40 {
    status=0; reason=""
    upload_check=$(grep -i "LimitRequestBody" /etc/httpd/conf/httpd.conf)
    if [ -z "$upload_check" ]; then
        status=1
        reason+="LimitRequestBody 설정 없음 → 업로드 제한 없음; "
    fi
    print_result "U-40" "웹서비스 업로드 및 다운로드 제한" "$status" "$reason"
}

########################################
# U-41 웹서비스 영역의 분리
########################################
function audit_41 {
    status=0; reason=""
    web_root=$(grep -i "^DocumentRoot" /etc/httpd/conf/httpd.conf | awk '{print $2}' | sed 's/"//g')
    if [ -z "$web_root" ]; then
        web_root="/var/www/html"
    fi

    if [[ "$web_root" == "/home"* || "$web_root" == "/root"* ]]; then
        status=1
        reason+="웹 루트가 /home 또는 /root 하위에 설정됨: $web_root; "
    fi
    print_result "U-41" "웹서비스 영역의 분리" "$status" "$reason"
}
########################################
# U-60 SSH 원격 접속 허용
########################################
function audit_60 {
    status=0; reason=""
    sshd_status=$(systemctl is-active sshd 2>/dev/null)
    if [ "$sshd_status" != "active" ]; then
        status=1
        reason="SSH 서비스 비활성화; "
    fi
    print_result "U-60" "SSH 원격 접속 허용" "$status" "$reason"
}
########################################
# U-61 ftp 서비스 확인
########################################
function audit_61 {
    status=0; reason=""
    if systemctl is-active --quiet vsftpd; then
        status=0
    else
        status=1
        reason="FTP 서비스 비활성 상태"
    fi
    print_result "U-61" "ftp 서비스 확인" "$status" "$reason"
}

########################################
# U-62 ftp 계정 shell 제한
########################################
function audit_62 {
    status=0; reason=""
    restricted_shells=("/sbin/nologin" "/bin/false")
    ftp_accounts=$(grep -E 'ftp|^ftp' /etc/passwd | cut -d: -f1)
    for user in $ftp_accounts; do
        user_shell=$(getent passwd "$user" | cut -d: -f7)
        if [[ ! " ${restricted_shells[*]} " =~ " ${user_shell} " ]]; then
            status=1
            reason+="FTP 계정 $user shell 제한 미설정; "
        fi
    done
    print_result "U-62" "ftp 계정 shell 제한" "$status" "$reason"
}

########################################
# U-63 Ftpusers 파일 소유자 및 권한 설정
########################################
function audit_63 {
    status=0; reason=""
    if [ -e /etc/ftpusers ]; then
        owner=$(stat -c %U /etc/ftpusers)
        perms=$(stat -c %a /etc/ftpusers)
        if [ "$owner" != "root" ]; then
            status=1
            reason+="/etc/ftpusers 소유자 root 아님; "
        fi
        if [ "$perms" -gt 640 ]; then
            status=1
            reason+="/etc/ftpusers 권한 너무 넓음 ($perms); "
        fi
    else
        status=1
        reason+="/etc/ftpusers 파일 없음; "
    fi
    print_result "U-63" "Ftpusers 파일 소유자 및 권한 설정" "$status" "$reason"
}

########################################
# U-64 Ftpusers 파일 설정
########################################
function audit_64 {
    status=0; reason=""
    if [ -e /etc/ftpusers ]; then
        if grep -q "^root" /etc/ftpusers && grep -q "^bin" /etc/ftpusers && grep -q "^daemon" /etc/ftpusers; then
            status=0
        else
            status=1
            reason+="기본 차단 계정 누락; "
        fi
    else
        status=1
        reason+="/etc/ftpusers 파일 없음; "
    fi
    print_result "U-64" "Ftpusers 파일 설정" "$status" "$reason"
}

########################################
# U-65 at 파일 소유자 및 권한 설정
########################################
function audit_65 {
    status=0; reason=""
    at_files=("/etc/at.allow" "/etc/at.deny")
    for file in "${at_files[@]}"; do
        if [ -e "$file" ]; then
            owner=$(stat -c %U "$file")
            perms=$(stat -c %a "$file")
            if [ "$owner" != "root" ]; then
                status=1
                reason+="$file 소유자 root 아님; "
            fi
            if [ "$perms" -gt 600 ]; then
                status=1
                reason+="$file 권한 너무 넓음 ($perms); "
            fi
        else
            # 파일이 없으면 상태 문제 없음 (파일 없을 수도 있음)
            continue
        fi
    done
    print_result "U-65" "at 파일 소유자 및 권한 설정" "$status" "$reason"
}

########################################
# U-66 SNMP 서비스 구동 점검
########################################
function audit_66 {
    status=0; reason=""
    if systemctl is-active --quiet snmpd; then
        status=0
    else
        status=1
        reason="SNMP 서비스 비활성화"
    fi
    print_result "U-66" "SNMP 서비스 구동 점검" "$status" "$reason"
}

########################################
# U-67 SNMP 서비스 커뮤니티스트링의 복잡성 설정
########################################
function audit_67 {
    status=0; reason=""
    conf_file="/etc/snmp/snmpd.conf"
    if [ -e "$conf_file" ]; then
        community=$(grep -E "^community" "$conf_file" | awk '{print $2}' | head -1)
        if [[ -z "$community" ]]; then
            status=1
            reason="community string 미설정"
        elif [[ "$community" == "public" || "$community" == "private" ]]; then
            status=1
            reason="기본 community string 사용(public/private)"
        fi
    else
        status=1
        reason="snmpd.conf 파일 없음"
    fi
    print_result "U-67" "SNMP 서비스 커뮤니티스트링의 복잡성 설정" "$status" "$reason"
}

########################################
# U-68 로그온 시 경고 메시지 제공
########################################
function audit_68 {
    status=0; reason=""
    # /etc/issue, /etc/motd 파일 점검
    if grep -q . /etc/issue || grep -q . /etc/motd; then
        status=0
    else
        status=1
        reason="로그온 경고 메시지 미설정"
    fi
    print_result "U-68" "로그온 시 경고 메시지 제공" "$status" "$reason"
}

########################################
# U-69 NFS 설정파일 접근 제한
########################################
function audit_69 {
    status=0; reason=""
    conf_files=("/etc/exports" "/etc/dfs/dfstab")
    for file in "${conf_files[@]}"; do
        if [ -e "$file" ]; then
            owner=$(stat -c %U "$file")
            perms=$(stat -c %a "$file")
            if [ "$owner" != "root" ]; then
                status=1
                reason+="$file 소유자 root 아님; "
            fi
            if [ "$perms" -gt 600 ]; then
                status=1
                reason+="$file 권한 너무 넓음 ($perms); "
            fi
        else
            # 파일 없으면 패스
            continue
        fi
    done
    print_result "U-69" "NFS 설정파일 접근 제한" "$status" "$reason"
}

########################################
# U-70 expn, vrfy 명령어 제한
########################################
function audit_70 {
    status=0; reason=""
    # postfix, sendmail 등 메일서버 설정파일에서 expn, vrfy 제한 확인
    # 여기서는 sendmail.mc 기준 예시
    if [ -e /etc/mail/sendmail.mc ]; then
        if grep -q "O PrivacyOptions=authwarnings,noexpn,novrfy" /etc/mail/sendmail.mc; then
            status=0
        else
            status=1
            reason="sendmail.mc에 expn, vrfy 제한 설정 없음"
        fi
    else
        status=1
        reason="sendmail.mc 파일 없음"
    fi
    print_result "U-70" "expn, vrfy 명령어 제한" "$status" "$reason"
}

########################################
# U-71 Apache 웹 서비스 정보 숨김
########################################
function audit_71 {
    status=0; reason=""
    conf_files=("/etc/httpd/conf/httpd.conf" "/etc/apache2/apache2.conf")
    found=0
    for conf in "${conf_files[@]}"; do
        if [ -e "$conf" ]; then
            if grep -q -E "ServerTokens\s+Prod" "$conf" && grep -q -E "ServerSignature\s+Off" "$conf"; then
                found=1
                break
            fi
        fi
    done
    if [ $found -eq 0 ]; then
        status=1
        reason="Apache 정보 숨김 설정 미적용"
    fi
    print_result "U-71" "Apache 웹 서비스 정보 숨김" "$status" "$reason"
}



### 실행(1번) ###
audit_1
audit_2
audit_3
audit_4
audit_44
audit_45
audit_46
audit_47
audit_48
audit_49
audit_50
audit_51
audit_52
audit_53
audit_54


######실행 3번#########
audit_19
audit_20
audit_21
audit_22
audit_23
audit_24
audit_25
audit_26
audit_27
audit_28
audit_29
audit_30
audit_31
audit_32
audit_33
audit_34
audit_35
#######승환님 파트########
### 실행 6번 ###
audit_36
audit_37
audit_38
audit_39
audit_40
audit_41
audit_60
audit_61
audit_62
audit_63
audit_64
audit_65
audit_66
audit_67
audit_68
audit_69
audit_70
audit_71


####################4번, 5번#################
audit_42
audit_43
audit_72



