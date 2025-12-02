#!/usr/bin/env python3
import os
import sys
import socket
import subprocess
import platform
import datetime
import shutil

# 전역 언어 설정
LANG = {}

def load_language(lang_code):
    # 언어 텍스트 파일에서 문자열 요소 불러옴
    global LANG
    filename = f"{lang_code}.txt"
    if not os.path.exists(filename):
        print(f"Language file {filename} not found. Defaulting to English keys.")
        return

    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    LANG[key] = value
    except Exception as e:
        print(f"Error loading language file: {e}")

def get_text(key, *args):
    # LANG 딕셔너리에서 문자열을 가져와 형식 지정 후 반환
    val = LANG.get(key, key) # 없으면 키 값 반환
    if args:
        try:
            return val.format(*args)
        except:
            return val
    return val

def log_message(message, results):
    # 메시지 콘솔에 출력, 결과 리스트에 추가
    print(message)
    results.append(message)

def run_command(command):
    # 셸 명령어 실행, 출력 반환
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing command: {e}"

def check_ports(results):
    # 열려 있는 포트 확인
    log_message(f"\n{get_text('PORT_HEADER')}", results)
    try:
        # netstat 또는 ss 사용해 리스닝 포트 검색
        if shutil.which("ss"):
            cmd = "ss -tuln"
        elif shutil.which("netstat"):
            cmd = "netstat -tuln"
        else:
            log_message(get_text('PORT_ERROR_TOOL'), results)
            return

        output = run_command(cmd)
        
        # 출력 필터링 및 포맷팅
        lines = output.splitlines()
        if lines:
            log_message("-" * 60, results)
            log_message(lines[0], results) # 헤더
            log_message("-" * 60, results)
            for line in lines[1:]:
                if "LISTEN" in line or "UNCONN" in line: # 리스닝 중인 UDP/TCP 포트 표시
                    log_message(line, results)
            log_message("-" * 60, results)
        else:
            log_message(output, results)
        
        # Well-known 포트 확인
        target_ports = {
            "20": "FTP Data",
            "21": "FTP Control",
            "22": "SSH",
            "23": "Telnet",
            "25": "SMTP",
            "69": "TFTP",
            "80": "HTTP",
            "443": "HTTPS",
            "3389": "RDP",
            "5900": "VNC"
        }
        
        log_message("\n[Specific Port Checks]", results)
        for port, label in target_ports.items():
            # 출력에 Well-known 포트 있는지 확인
            is_open = False
            for line in lines:
                # 일반적인 패턴 확인: :포트 뒤 공백 또는 줄 끝이 오는지 확인
                if f":{port} " in line or f":{port}\t" in line or line.endswith(f":{port}"):
                    is_open = True
                    break
            
            if is_open:
                log_message(get_text('PORT_SPECIFIC_OPEN', port, label), results)
            else:
                log_message(get_text('PORT_SPECIFIC_CLOSED', port, label), results)
        
    except Exception as e:
        log_message(f"{get_text('PORT_ERROR_EXEC')} {e}", results)

def check_accounts(results):
    # 계정 취약점 확인
    log_message(f"\n{get_text('ACCOUNT_HEADER')}", results)
    
    # root 권한 확인
    if os.geteuid() != 0:
        log_message(get_text('ACCOUNT_ROOT_WARN'), results)

    # 빈 비밀번호 확인
    try:
        if os.access("/etc/shadow", os.R_OK):
            with open("/etc/shadow", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1 and (parts[1] == "" or parts[1] == "!" or parts[1] == "*"):
                        continue 
                    elif len(parts) > 1 and len(parts[1]) < 5: 
                         log_message(get_text('ACCOUNT_PASS_WARN', parts[0]), results)
        else:
             log_message(get_text('ACCOUNT_SHADOW_INFO'), results)
    except Exception as e:
        log_message(f"{get_text('ACCOUNT_SHADOW_ERROR')} {e}", results)

    # root 외 UID 0 계정 확인
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                    log_message(get_text('ACCOUNT_UID0_CRIT', parts[0]), results)
    except Exception as e:
        log_message(f"{get_text('ACCOUNT_PASSWD_ERROR')} {e}", results)

def check_ssh(results):
    # SSH 접근 권한 확인
    log_message(f"\n{get_text('SSH_HEADER')}", results)
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        try:
            with open(ssh_config, "r") as f:
                config_content = f.read()
                
            if "PermitRootLogin yes" in config_content:
                log_message(get_text('SSH_ROOT_WARN'), results)
            
            if "PasswordAuthentication yes" in config_content:
                 log_message(get_text('SSH_PASS_INFO'), results)
                 
            if "Protocol 1" in config_content:
                log_message(get_text('SSH_PROTO_CRIT'), results)
                
        except Exception as e:
            log_message(f"{get_text('SSH_CONFIG_ERROR')} {e}", results)
    else:
        log_message(get_text('SSH_NOT_FOUND'), results)

def check_packages(results):
    # 오래된 패키지 및 OS 패치 확인
    log_message(f"\n{get_text('PKG_HEADER')}", results)
    
    distro = "unknown"
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read().lower()
                if "id=debian" in content or "id=ubuntu" in content:
                    distro = "debian"
                elif "id=centos" in content or "id=rhel" in content or "id=fedora" in content:
                    distro = "redhat"
    except:
        pass

    if distro == "debian":
        log_message(get_text('PKG_DEBIAN'), results)
        # apt-get -s upgrade | grep "^Inst" 명령어를 사용, 업데이트 확인
        output = run_command('apt-get -s upgrade | grep "^Inst"')
        if output:
             log_message(get_text('PKG_UPDATES'), results)
             log_message(output, results)
        else:
             log_message(get_text('PKG_UPTODATE'), results)
             
    elif distro == "redhat":
        log_message(get_text('PKG_REDHAT'), results)
        output = run_command("yum check-update")
        if output:
             log_message(get_text('PKG_UPDATES'), results)
             log_message(output, results)
        else:
             log_message(get_text('PKG_UPTODATE'), results)
    else:
        log_message(get_text('PKG_UNKNOWN'), results)

def check_firewall(results):
    # 방화벽 상태 확인
    log_message(f"\n{get_text('FW_HEADER')}", results)
    
    if shutil.which("ufw"):
        output = run_command("ufw status")
        log_message(f"{get_text('FW_STATUS_UFW')}\n{output}", results)
    elif shutil.which("firewall-cmd"):
        output = run_command("firewall-cmd --state")
        log_message(f"{get_text('FW_STATUS_FIREWALLD')} {output}", results)
    elif shutil.which("iptables"):
        output = run_command("iptables -L -n | head -n 10")
        log_message(f"{get_text('FW_STATUS_IPTABLES')}\n{output}...", results)
    else:
        log_message(get_text('FW_NOT_FOUND'), results)

def check_directories(results):
    # 디렉토리 권한 확인
    log_message(f"\n{get_text('DIR_HEADER')}", results)
    
    # /var/log, /home, /root, /var/www 디렉토리 추가
    critical_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/log", "/home", "/root", "/var/www"]
    
    for d in critical_dirs:
        if os.path.exists(d):
            stat_info = os.stat(d)
            mode = stat_info.st_mode
            # 전체 쓰기 가능 여부 확인
            if mode & 0o002:
                if d == "/tmp":
                    # /tmp 고정 비트 확인(전체 쓰기는 허가)
                    if not (mode & 0o1000):
                         log_message(get_text('DIR_TMP_WARN', d), results)
                else:
                    log_message(get_text('DIR_WARN', d), results)
            else:
                log_message(get_text('DIR_OK', d), results)

def save_report(results):
    # 분석 결과를 텍스트 파일로 저장
    # 로그 디렉토리 생성
    log_dir = "log"
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        print(f"Error creating log directory: {e}")
        return

    filename = f"security_audit_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(log_dir, filename)
    
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(results))
        print(f"\n{get_text('REPORT_SAVED')} {os.path.abspath(filepath)}")
    except Exception as e:
        print(f"{get_text('REPORT_ERROR')} {e}")

def main():
    # 언어 인자 처리
    lang_code = None
    
    # 명령줄 인자 확인 (.py 뒤)
    if len(sys.argv) > 1:
        arg_lang = sys.argv[1]
        if os.path.exists(f"{arg_lang}.txt"):
            lang_code = arg_lang
        else:
            print(f"Warning: Language file '{arg_lang}.txt' not found. Attempting auto-detection.")
    
    # 유효한 인자가 없을 시 시스템 로케일 확인 
    if not lang_code:
        try:
            # 기본 로케일 가져오기 시도
            import locale
            sys_lang, _ = locale.getdefaultlocale()
            if not sys_lang:
                # 환경 변수로 대체
                sys_lang = os.environ.get('LANG', '')
            
            if sys_lang:
                detected_lang = sys_lang.split('_')[0].lower()
                if os.path.exists(f"{detected_lang}.txt"):
                    lang_code = detected_lang
        except:
            pass
    
    # 다른 언어를 찾지 못하면 기본값인 영어로 설정
    if not lang_code:
        lang_code = 'en'
    
    load_language(lang_code)

    results = []
    log_message(f"{get_text('START_MSG')} {datetime.datetime.now()}", results)
    
    check_ports(results)
    check_accounts(results)
    check_ssh(results)
    check_packages(results)
    check_firewall(results)
    check_directories(results)
    
    save_report(results)

if __name__ == "__main__":
    main()