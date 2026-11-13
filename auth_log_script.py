from collections import defaultdict, deque
import json
import time
import re

# Open auth.log and move to the end
with open("/var/log/auth.log", "r") as file:

    file.seek(0, 2)

    # track attempts separately for each IP, per service
    ssh_attempts = defaultdict(deque)
    failed_attempts = defaultdict(deque)
    ftp_attempts = defaultdict(deque)
    rdp_attempts = defaultdict(deque)
    web_attempts = defaultdict(deque)
    db_attempts = defaultdict(deque)
    email_attempts = defaultdict(deque)
    vpn_attempts = defaultdict(deque)

    # track which IPs have already triggered alerts, per service
    ssh_alerted = set() #ssh brute force
    login_alerted = set() #general failed logins
    ftp_alerted = set() #ftp brute force
    rdp_alerted = set() #rdp brute force
    web_alerted = set() #web login brute force
    db_alerted = set() #database brute force
    email_alerted = set() #email login brute force
    vpn_alerted = set() #vpn brute force

    open("auth_alerts.jsonl", "a").close() # Ensure the output file exists

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        srcIP = None
        alrType = None
        svrType = None
        msg = None

        #check for repeated general failed logins
        #any failed / authentication failure line containing: from IP
        login_ip = None

        if "failed" in line.lower() or "authentication failure" in line.lower():
            login_ip = re.search(r"from (\S+)", line)

        if login_ip:
            srcIP = login_ip.group(1)
            now = time.time()

            failed_attempts[srcIP].append(now)

            #remove failed login attempts older than 60 seconds
            while failed_attempts[srcIP] and now - failed_attempts[srcIP][0] > 60:
                failed_attempts[srcIP].popleft()

            if len(failed_attempts[srcIP]) >= 5 and srcIP not in login_alerted:
                alrType = "Repeated Failed Logins"
                svrType = "Medium"
                msg = "5 or more failed authentication attempts from this IP in 60 seconds"
                login_alerted.add(srcIP)

            if len(failed_attempts[srcIP]) < 5:
                login_alerted.discard(srcIP)

        #check for SSH brute force
        #sshd: Failed password for x from IP port N ssh2
        ssh_ip = None

        if "sshd" in line.lower() and ("failed" in line.lower() or "authentication failure" in line.lower()):
            ssh_ip = re.search(r"from (\S+)", line)

        if ssh_ip:
            srcIP = ssh_ip.group(1)
            now = time.time()

            ssh_attempts[srcIP].append(now)

            #remove SSH attempts older than 60 seconds
            while ssh_attempts[srcIP] and now - ssh_attempts[srcIP][0] > 60:
                ssh_attempts[srcIP].popleft()

            if len(ssh_attempts[srcIP]) >= 15 and srcIP not in ssh_alerted:
                alrType = "SSH Brute Force"
                svrType = "High"
                msg = "15 or more failed SSH attempts in 60 seconds"
                ssh_alerted.add(srcIP)

            if len(ssh_attempts[srcIP]) < 15:
                ssh_alerted.discard(srcIP)

        #check for FTP brute force
        #vsftpd: FAIL LOGIN: Client "::ffff:IP" / proftpd: (IP[IP]): USER x (Login failed)
        ftp_ip = re.search(r'FAIL LOGIN: Client "(?:::ffff:)?([^"]+)"', line) or re.search(r"\(\S*\[([^\]]+)\]\):.*Login failed", line)

        if ftp_ip:
            srcIP = ftp_ip.group(1)
            now = time.time()

            ftp_attempts[srcIP].append(now)

            #remove FTP attempts older than 60 seconds
            while ftp_attempts[srcIP] and now - ftp_attempts[srcIP][0] > 60:
                ftp_attempts[srcIP].popleft()

            if len(ftp_attempts[srcIP]) >= 15 and srcIP not in ftp_alerted:
                alrType = "FTP Brute Force"
                svrType = "High"
                msg = "15 or more failed FTP attempts in 60 seconds"
                ftp_alerted.add(srcIP)

            if len(ftp_attempts[srcIP]) < 15:
                ftp_alerted.discard(srcIP)

        #check for RDP brute force
        #xrdp-sesman: AUTHFAIL: user=x ip=::ffff:IP
        rdp_ip = re.search(r"AUTHFAIL:.*?ip=(?:::ffff:)?(\S+)", line)

        if rdp_ip:
            srcIP = rdp_ip.group(1)
            now = time.time()

            rdp_attempts[srcIP].append(now)

            #remove RDP attempts older than 60 seconds
            while rdp_attempts[srcIP] and now - rdp_attempts[srcIP][0] > 60:
                rdp_attempts[srcIP].popleft()

            if len(rdp_attempts[srcIP]) >= 15 and srcIP not in rdp_alerted:
                alrType = "RDP Brute Force"
                svrType = "High"
                msg = "15 or more failed RDP attempts in 60 seconds"
                rdp_alerted.add(srcIP)

            if len(rdp_attempts[srcIP]) < 15:
                rdp_alerted.discard(srcIP)

        #check for web login brute force
        #access log: IP - user [time] "METHOD PATH PROTO" STATUS
        web = re.search(r'(\S+) \S+ (\S+) \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3})', line)
        web_ip = None

        if web:
            webPath = web.group(4).split("?")[0].lower()

            #basic auth: credentials given but rejected
            if web.group(5) == "401" and web.group(2) != "-":
                web_ip = web.group(1)
            #login form rejected
            elif web.group(3) == "POST" and webPath.startswith(("/login", "/signin", "/wp-login.php", "/admin", "/user/login", "/auth", "/api/login")) and web.group(5) in ("401", "403"):
                web_ip = web.group(1)
            #wordpress returns 200 on a failed login (302 on success)
            elif web.group(3) == "POST" and webPath.endswith("/wp-login.php") and web.group(5) == "200":
                web_ip = web.group(1)

        if web_ip:
            srcIP = web_ip
            now = time.time()

            web_attempts[srcIP].append(now)

            #remove web login attempts older than 60 seconds
            while web_attempts[srcIP] and now - web_attempts[srcIP][0] > 60:
                web_attempts[srcIP].popleft()

            if len(web_attempts[srcIP]) >= 15 and srcIP not in web_alerted:
                alrType = "Web Login Brute Force"
                svrType = "High"
                msg = "15 or more failed web login attempts in 60 seconds"
                web_alerted.add(srcIP)

            if len(web_attempts[srcIP]) < 15:
                web_alerted.discard(srcIP)

        #check for database brute force
        #mysql: Access denied for user 'x'@'IP' / postgresql (host=%h in log_line_prefix): host=IP ... authentication failed for user
        db_ip = re.search(r"Access denied for user '[^']*'@'([^']+)'", line) or re.search(r"host=(\S+).*authentication failed for user", line)

        if db_ip:
            srcIP = db_ip.group(1)
            now = time.time()

            db_attempts[srcIP].append(now)

            #remove database attempts older than 60 seconds
            while db_attempts[srcIP] and now - db_attempts[srcIP][0] > 60:
                db_attempts[srcIP].popleft()

            if len(db_attempts[srcIP]) >= 15 and srcIP not in db_alerted:
                alrType = "Database Brute Force"
                svrType = "High"
                msg = "15 or more failed database attempts in 60 seconds"
                db_alerted.add(srcIP)

            if len(db_attempts[srcIP]) < 15:
                db_alerted.discard(srcIP)

        #check for email login brute force
        #dovecot: imap-login: ... (auth failed, N attempts ...) ... rip=IP / postfix: [IP]: SASL LOGIN authentication failed
        email_ip = re.search(r"-login:.*auth failed.*rip=([^,\s]+)", line) or re.search(r"\[([^\]]+)\]: SASL \S+ authentication failed", line)

        if email_ip:
            srcIP = email_ip.group(1)
            now = time.time()

            #dovecot can report several failed attempts in one line
            email_count = re.search(r"auth failed, (\d+) attempts", line)

            for _ in range(int(email_count.group(1)) if email_count else 1):
                email_attempts[srcIP].append(now)

            #remove email attempts older than 60 seconds
            while email_attempts[srcIP] and now - email_attempts[srcIP][0] > 60:
                email_attempts[srcIP].popleft()

            if len(email_attempts[srcIP]) >= 15 and srcIP not in email_alerted:
                alrType = "Email Login Brute Force"
                svrType = "High"
                msg = "15 or more failed email login attempts in 60 seconds"
                email_alerted.add(srcIP)

            if len(email_attempts[srcIP]) < 15:
                email_alerted.discard(srcIP)

        #check for VPN brute force
        #openvpn: IP:port TLS Auth Error: Auth Username/Password verification failed for peer
        vpn_ip = None

        if "Auth Username/Password verification failed" in line or "AUTH_FAILED" in line:
            vpn_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", line)

        if vpn_ip:
            srcIP = vpn_ip.group(1)
            now = time.time()

            vpn_attempts[srcIP].append(now)

            #remove VPN attempts older than 60 seconds
            while vpn_attempts[srcIP] and now - vpn_attempts[srcIP][0] > 60:
                vpn_attempts[srcIP].popleft()

            if len(vpn_attempts[srcIP]) >= 15 and srcIP not in vpn_alerted:
                alrType = "VPN Brute Force"
                svrType = "High"
                msg = "15 or more failed VPN attempts in 60 seconds"
                vpn_alerted.add(srcIP)

            if len(vpn_attempts[srcIP]) < 15:
                vpn_alerted.discard(srcIP)

        #export alert if one was generated
        if alrType is not None:

            alert = {
                "source": "auth.log",
                "source_ip": srcIP,
                "alert_type": alrType,
                "severity": svrType,
                "message": msg,
                "raw_log": line.strip(),
                "time": int(time.time())
            }

            #save each alert to the JSONL file
            with open("auth_alerts.jsonl", "a") as output:
                output.write(json.dumps(alert) + "\n")


            