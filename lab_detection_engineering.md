# Lab v1.0 — Zeek Detection Pack

> **Environment:** Security Onion 2.4 · Standalone · Monitor interface `enp0s8`
> **Author:** Joseph Asante · SOC Lab
> **Version:** 1.0 · April 2026

---

## Overview

This detection pack provides Zeek scripts that complement the Suricata ruleset. While Suricata excels at signature-based alerting, Zeek adds **behavioral analysis**, **metadata extraction**, and **protocol-aware logging** that enables deeper threat hunting and investigation.

### What's Included

| Script | Detection Target | Complements SID Range |
|--------|------------------|-----------------------|
| `reverse-shell.zeek` | Reverse shell sessions | 1000001–1000009 |
| `http-exfil.zeek` | HTTP data exfiltration | 1000010–1000017 |
| `dns-tunnel.zeek` | DNS tunneling | 1000020–1000026 |
| `web-attacks.zeek` | Web application attacks | 1000030–1000039 |
| `brute-force.zeek` | Brute force attempts | 1000040–1000046 |
| `beaconing.zeek` | C2 beaconing patterns | 1000050–1000055 |
| `suspicious-ua.zeek` | Suspicious user-agents | 1000070–1000078 |

### Deployment on Security Onion 2.4

```bash
# 1. Navigate to the local Zeek scripts directory
cd /opt/so/saltstack/local/salt/zeek/policy/

# 2. Create the lab detections directory
sudo mkdir -p lab-v1

# 3. Copy each .zeek script into this directory
#    (use the filenames from the sections below)

# 4. Create a __load__.zeek to auto-load all scripts
sudo bash -c 'cat > lab-v1/__load__.zeek << EOF
@load ./reverse-shell
@load ./http-exfil
@load ./dns-tunnel
@load ./web-attacks
@load ./brute-force
@load ./beaconing
@load ./suspicious-ua
EOF'

# 5. Add the lab pack to the local Zeek configuration
echo "@load lab-v1" | sudo tee -a local.zeek

# 6. Restart Zeek to apply
sudo so-zeek-restart

# 7. Verify scripts are loaded
sudo so-zeek-status
tail -f /nsm/zeek/logs/current/loaded_scripts.log
```

---

## Script 1 — Reverse Shell Detection

**File:** `reverse-shell.zeek`

This script detects interactive shell sessions by analyzing connection patterns and payload content.

```zeek
##! Reverse Shell Detection for Lab v1.0
##! Detects interactive shell sessions over TCP
##! MITRE ATT&CK: T1059.004

module LabDetect;

export {
    ## Notice type for reverse shell detection
    redef enum Notice::Type += {
        Reverse_Shell_Detected,
        Reverse_Shell_Interactive,
    };

    ## Minimum bytes exchanged to consider interactive
    const interactive_threshold: count = 200 &redef;

    ## Ports commonly used for reverse shells
    const suspicious_ports: set[port] = {
        4444/tcp, 4445/tcp, 4446/tcp,    # Metasploit defaults
        5555/tcp, 6666/tcp, 7777/tcp,    # Common attacker ports
        8888/tcp, 9999/tcp, 1234/tcp,    # Common attacker ports
        31337/tcp,                        # Elite/leet port
    } &redef;
}

## Track connections on suspicious ports with bidirectional data
event connection_state_remove(c: connection) {
    # Only check established TCP connections
    if ( c$conn$proto != tcp )
        return;

    # Check for suspicious ports
    if ( c$id$resp_p !in suspicious_ports && c$id$orig_p !in suspicious_ports )
        return;

    # Look for bidirectional interactive traffic
    if ( c$conn?$orig_bytes && c$conn?$resp_bytes ) {
        local orig_bytes = c$conn$orig_bytes;
        local resp_bytes = c$conn$resp_bytes;

        # Interactive shell: both sides exchange data
        if ( orig_bytes > interactive_threshold && resp_bytes > interactive_threshold ) {
            local ratio = (orig_bytes * 1.0) / (resp_bytes * 1.0);

            # Shell sessions typically have roughly balanced traffic
            if ( ratio > 0.1 && ratio < 10.0 ) {
                NOTICE([
                    $note = Reverse_Shell_Interactive,
                    $msg = fmt("Possible interactive reverse shell: %s -> %s:%s (%d/%d bytes)",
                               c$id$orig_h, c$id$resp_h, c$id$resp_p,
                               orig_bytes, resp_bytes),
                    $conn = c,
                    $identifier = cat(c$id$orig_h, c$id$resp_h, c$id$resp_p),
                    $suppress_for = 5min,
                ]);
            }
        }
    }
}

## Detect shell signatures in connection content
event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string) {

    if ( |payload| < 5 )
        return;

    # Check for common shell prompts and commands
    if ( /uid=[0-9]+\(/ in payload ||
         /root@/ in payload ||
         /\/bin\/(sh|bash|zsh)/ in payload ||
         /\$\s+(whoami|id|uname|pwd|ls|cat)/ in payload ) {

        NOTICE([
            $note = Reverse_Shell_Detected,
            $msg = fmt("Shell signature in traffic: %s <-> %s:%s",
                       c$id$orig_h, c$id$resp_h, c$id$resp_p),
            $conn = c,
            $identifier = cat(c$id$orig_h, c$id$resp_h),
            $suppress_for = 1min,
        ]);
    }
}
```

---

## Script 2 — HTTP Data Exfiltration Detection

**File:** `http-exfil.zeek`

Monitors HTTP traffic for signs of data leaving the network, including large uploads, sensitive content patterns, and unusual methods.

```zeek
##! HTTP Data Exfiltration Detection for Lab v1.0
##! Monitors for suspicious outbound HTTP data transfers
##! MITRE ATT&CK: T1048.003

module LabDetect;

export {
    redef enum Notice::Type += {
        HTTP_Large_Upload,
        HTTP_Sensitive_Data_Exfil,
        HTTP_Unusual_Method,
        HTTP_NonStandard_Port,
    };

    ## Threshold for "large" HTTP POST body (bytes)
    const large_post_threshold: count = 10000 &redef;

    ## Internal network definition
    const monitored_nets: set[subnet] = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } &redef;
}

## Create a custom log for exfiltration events
redef enum Log::ID += { EXFIL_LOG };

type ExfilInfo: record {
    ts:             time        &log;
    uid:            string      &log;
    src:            addr        &log;
    dst:            addr        &log;
    method:         string      &log;
    host:           string      &log;
    uri:            string      &log;
    request_len:    count       &log;
    user_agent:     string      &log &default="(none)";
    alert_type:     string      &log;
};

event zeek_init() {
    Log::create_stream(EXFIL_LOG, [$columns=ExfilInfo, $path="lab-exfil"]);
}

## Monitor HTTP requests for exfiltration indicators
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {

    # Only monitor outbound traffic from internal hosts
    if ( c$id$orig_h !in monitored_nets )
        return;

    # Flag unusual HTTP methods
    if ( method == "PUT" || method == "PATCH" || method == "DELETE" ) {
        NOTICE([
            $note = HTTP_Unusual_Method,
            $msg = fmt("Unusual HTTP method %s from %s to %s%s",
                       method, c$id$orig_h, c$http$host, original_URI),
            $conn = c,
            $identifier = cat(c$id$orig_h, method),
            $suppress_for = 5min,
        ]);

        Log::write(EXFIL_LOG, ExfilInfo($ts=network_time(), $uid=c$uid,
            $src=c$id$orig_h, $dst=c$id$resp_h, $method=method,
            $host=c$http$host, $uri=original_URI,
            $request_len=0, $alert_type="unusual_method"));
    }

    # Flag HTTP on non-standard ports
    if ( c$id$resp_p != 80/tcp && c$id$resp_p != 8080/tcp && method == "POST" ) {
        NOTICE([
            $note = HTTP_NonStandard_Port,
            $msg = fmt("HTTP POST on non-standard port %s from %s",
                       c$id$resp_p, c$id$orig_h),
            $conn = c,
            $identifier = cat(c$id$orig_h, c$id$resp_p),
            $suppress_for = 10min,
        ]);
    }
}

## Check POST body sizes after the full request is seen
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {

    if ( ! is_orig )
        return;

    if ( c$id$orig_h !in monitored_nets )
        return;

    if ( ! c$http?$method || c$http$method != "POST" )
        return;

    # Check for large POST body
    if ( stat$body_length > large_post_threshold ) {
        NOTICE([
            $note = HTTP_Large_Upload,
            $msg = fmt("Large HTTP POST (%d bytes) from %s to %s",
                       stat$body_length, c$id$orig_h,
                       c$http?$host ? c$http$host : cat(c$id$resp_h)),
            $conn = c,
            $identifier = cat(c$id$orig_h, c$id$resp_h),
            $suppress_for = 5min,
        ]);

        Log::write(EXFIL_LOG, ExfilInfo($ts=network_time(), $uid=c$uid,
            $src=c$id$orig_h, $dst=c$id$resp_h,
            $method="POST",
            $host=c$http?$host ? c$http$host : cat(c$id$resp_h),
            $uri=c$http?$uri ? c$http$uri : "(unknown)",
            $request_len=stat$body_length,
            $user_agent=c$http?$user_agent ? c$http$user_agent : "(none)",
            $alert_type="large_post"));
    }
}
```

---

## Script 3 — DNS Tunneling Detection

**File:** `dns-tunnel.zeek`

Detects DNS tunneling by analyzing query length, entropy, query volume, and TXT record abuse.

```zeek
##! DNS Tunneling Detection for Lab v1.0
##! Analyzes DNS queries for tunneling indicators
##! MITRE ATT&CK: T1071.004

module LabDetect;

export {
    redef enum Notice::Type += {
        DNS_Long_Query,
        DNS_High_Volume,
        DNS_TXT_Abuse,
        DNS_High_Entropy,
    };

    ## Minimum label length to flag
    const dns_long_label_min: count = 50 &redef;

    ## DNS query count threshold per source per minute
    const dns_volume_threshold: count = 100 &redef;

    ## DNS volume tracking window
    const dns_volume_window: interval = 1min &redef;
}

## Track DNS query counts per source
global dns_query_counts: table[addr] of count &create_expire=2min &default=0;

## Custom log for DNS tunnel indicators
redef enum Log::ID += { DNS_TUNNEL_LOG };

type DNSTunnelInfo: record {
    ts:         time        &log;
    src:        addr        &log;
    query:      string      &log;
    qtype:      string      &log;
    query_len:  count       &log;
    alert_type: string      &log;
};

event zeek_init() {
    Log::create_stream(DNS_TUNNEL_LOG, [$columns=DNSTunnelInfo, $path="lab-dns-tunnel"]);
}

## Calculate Shannon entropy of a string
function shannon_entropy(s: string): double {
    local freq: table[string] of count;
    local len = |s|;

    if ( len == 0 )
        return 0.0;

    # Count character frequencies
    for ( i in s ) {
        local ch = s[i];
        if ( ch !in freq )
            freq[ch] = 0;
        freq[ch] += 1;
    }

    local entropy = 0.0;
    for ( ch, cnt in freq ) {
        local p = (cnt * 1.0) / (len * 1.0);
        if ( p > 0.0 )
            entropy -= p * (ln(p) / ln(2.0));
    }

    return entropy;
}

## Analyze each DNS query
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {

    local src = c$id$orig_h;

    # --- Volume tracking ---
    dns_query_counts[src] += 1;
    if ( dns_query_counts[src] == dns_volume_threshold ) {
        NOTICE([
            $note = DNS_High_Volume,
            $msg = fmt("Host %s exceeded %d DNS queries in tracking window",
                       src, dns_volume_threshold),
            $src = src,
            $identifier = cat(src),
            $suppress_for = 5min,
        ]);
    }

    # --- Long subdomain detection ---
    local parts = split_string(query, /\./);
    for ( idx, part in parts ) {
        if ( |part| >= dns_long_label_min ) {
            NOTICE([
                $note = DNS_Long_Query,
                $msg = fmt("DNS query with long label (%d chars) from %s: %s",
                           |part|, src, query),
                $src = src,
                $identifier = cat(src, query),
                $suppress_for = 1min,
            ]);

            Log::write(DNS_TUNNEL_LOG, DNSTunnelInfo($ts=network_time(),
                $src=src, $query=query, $qtype=fmt("%d", qtype),
                $query_len=|query|, $alert_type="long_label"));
            break;
        }
    }

    # --- High entropy detection ---
    # Extract the first subdomain label
    if ( |parts| >= 2 ) {
        local first_label = parts[0];
        if ( |first_label| > 10 ) {
            local ent = shannon_entropy(first_label);
            if ( ent > 3.5 ) {
                Log::write(DNS_TUNNEL_LOG, DNSTunnelInfo($ts=network_time(),
                    $src=src, $query=query, $qtype=fmt("%d", qtype),
                    $query_len=|query|, $alert_type=fmt("high_entropy_%.2f", ent)));

                if ( ent > 4.0 ) {
                    NOTICE([
                        $note = DNS_High_Entropy,
                        $msg = fmt("High entropy DNS label (%.2f) from %s: %s",
                                   ent, src, query),
                        $src = src,
                        $identifier = cat(src, query),
                        $suppress_for = 1min,
                    ]);
                }
            }
        }
    }

    # --- TXT record abuse ---
    # qtype 16 = TXT
    if ( qtype == 16 ) {
        NOTICE([
            $note = DNS_TXT_Abuse,
            $msg = fmt("DNS TXT query from %s: %s", src, query),
            $src = src,
            $identifier = cat(src, query),
            $suppress_for = 5min,
        ]);

        Log::write(DNS_TUNNEL_LOG, DNSTunnelInfo($ts=network_time(),
            $src=src, $query=query, $qtype="TXT",
            $query_len=|query|, $alert_type="txt_query"));
    }
}
```

---

## Script 4 — Web Application Attack Detection

**File:** `web-attacks.zeek`

Detects SQL injection, XSS, directory traversal, and command injection in HTTP URIs and headers.

```zeek
##! Web Application Attack Detection for Lab v1.0
##! Inspects HTTP URIs and parameters for attack patterns
##! MITRE ATT&CK: T1190

module LabDetect;

export {
    redef enum Notice::Type += {
        SQL_Injection_Attempt,
        XSS_Attempt,
        Directory_Traversal,
        Command_Injection,
        Remote_File_Include,
    };
}

## Custom log for web attacks
redef enum Log::ID += { WEB_ATTACK_LOG };

type WebAttackInfo: record {
    ts:         time        &log;
    uid:        string      &log;
    src:        addr        &log;
    dst:        addr        &log;
    method:     string      &log;
    host:       string      &log;
    uri:        string      &log;
    user_agent: string      &log &default="(none)";
    attack_type: string     &log;
};

event zeek_init() {
    Log::create_stream(WEB_ATTACK_LOG, [$columns=WebAttackInfo, $path="lab-web-attacks"]);
}

## Helper to log and notice web attacks
function report_web_attack(c: connection, attack_type: string, notice_type: Notice::Type) {
    local uri = c$http?$uri ? c$http$uri : "(unknown)";
    local host = c$http?$host ? c$http$host : cat(c$id$resp_h);
    local method = c$http?$method ? c$http$method : "(unknown)";

    NOTICE([
        $note = notice_type,
        $msg = fmt("%s from %s targeting %s%s",
                   attack_type, c$id$orig_h, host, uri),
        $conn = c,
        $identifier = cat(c$id$orig_h, attack_type),
        $suppress_for = 1min,
    ]);

    Log::write(WEB_ATTACK_LOG, WebAttackInfo(
        $ts=network_time(), $uid=c$uid,
        $src=c$id$orig_h, $dst=c$id$resp_h,
        $method=method, $host=host, $uri=uri,
        $user_agent=c$http?$user_agent ? c$http$user_agent : "(none)",
        $attack_type=attack_type));
}

## Inspect HTTP requests for attack patterns
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {

    local uri_lower = to_lower(unescaped_URI);

    # --- SQL Injection ---
    if ( /union\s+(all\s+)?select/ in uri_lower ||
         /'\s*or\s+['0-9]/ in uri_lower ||
         /;\s*(drop|delete|insert|update)\s/ in uri_lower ||
         /'\s*--\s*$/ in uri_lower ||
         /1\s*=\s*1/ in uri_lower ) {
        report_web_attack(c, "SQL Injection", SQL_Injection_Attempt);
    }

    # --- Cross-Site Scripting (XSS) ---
    if ( /<script/i in uri_lower ||
         /javascript\s*:/i in uri_lower ||
         /(onerror|onload|onmouseover|onfocus)\s*=/i in uri_lower ||
         /document\.(cookie|location|write)/i in uri_lower ||
         /alert\s*\(/i in uri_lower ) {
        report_web_attack(c, "XSS", XSS_Attempt);
    }

    # --- Directory Traversal ---
    if ( /\.\.\// in original_URI ||
         /\.\.\\/ in original_URI ||
         /\/etc\/passwd/ in uri_lower ||
         /\/etc\/shadow/ in uri_lower ||
         /\/windows\/system32/ in uri_lower ) {
        report_web_attack(c, "Directory Traversal", Directory_Traversal);
    }

    # --- Command Injection ---
    if ( /[;|`]\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|netcat)/ in uri_lower ||
         /\$\(/ in original_URI ) {
        report_web_attack(c, "Command Injection", Command_Injection);
    }

    # --- Remote File Inclusion ---
    if ( /(file|page|include|path|url)\s*=\s*https?:\/\// in uri_lower ) {
        report_web_attack(c, "Remote File Include", Remote_File_Include);
    }
}
```

---

## Script 5 — Brute Force Detection

**File:** `brute-force.zeek`

Tracks failed authentication attempts across SSH, FTP, HTTP, and other services.

```zeek
##! Brute Force Detection for Lab v1.0
##! Threshold-based detection for repeated auth failures
##! MITRE ATT&CK: T1110

module LabDetect;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force,
        FTP_Brute_Force,
        HTTP_Brute_Force,
    };

    ## Number of failures before alerting
    const brute_force_threshold: count = 5 &redef;

    ## Time window for tracking failures
    const brute_force_window: interval = 5min &redef;
}

## Track authentication failures per source
global ssh_failures: table[addr] of count &create_expire=10min &default=0;
global ftp_failures: table[addr] of count &create_expire=10min &default=0;
global http_failures: table[addr] of count &create_expire=10min &default=0;

## Custom log
redef enum Log::ID += { BRUTE_FORCE_LOG };

type BruteForceInfo: record {
    ts:         time        &log;
    src:        addr        &log;
    dst:        addr        &log;
    service:    string      &log;
    failures:   count       &log;
};

event zeek_init() {
    Log::create_stream(BRUTE_FORCE_LOG, [$columns=BruteForceInfo, $path="lab-brute-force"]);
}

## SSH authentication failures
event ssh_auth_result(c: connection, result: bool, direction: count) {
    if ( result )
        return;

    local src = c$id$orig_h;
    ssh_failures[src] += 1;

    if ( ssh_failures[src] == brute_force_threshold ) {
        NOTICE([
            $note = SSH_Brute_Force,
            $msg = fmt("SSH brute force: %s has %d failed attempts against %s",
                       src, ssh_failures[src], c$id$resp_h),
            $src = src,
            $identifier = cat(src, "ssh"),
            $suppress_for = 10min,
        ]);

        Log::write(BRUTE_FORCE_LOG, BruteForceInfo(
            $ts=network_time(), $src=src, $dst=c$id$resp_h,
            $service="ssh", $failures=ssh_failures[src]));
    }
}

## FTP authentication failures (530 response)
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) {
    if ( code != 530 )
        return;

    local src = c$id$orig_h;
    ftp_failures[src] += 1;

    if ( ftp_failures[src] == brute_force_threshold ) {
        NOTICE([
            $note = FTP_Brute_Force,
            $msg = fmt("FTP brute force: %s has %d failed logins against %s",
                       src, ftp_failures[src], c$id$resp_h),
            $src = src,
            $identifier = cat(src, "ftp"),
            $suppress_for = 10min,
        ]);

        Log::write(BRUTE_FORCE_LOG, BruteForceInfo(
            $ts=network_time(), $src=src, $dst=c$id$resp_h,
            $service="ftp", $failures=ftp_failures[src]));
    }
}

## HTTP authentication failures (401/403)
event http_reply(c: connection, version: string, code: count, reason: string) {
    if ( code != 401 && code != 403 )
        return;

    local src = c$id$orig_h;
    http_failures[src] += 1;

    if ( http_failures[src] == brute_force_threshold ) {
        NOTICE([
            $note = HTTP_Brute_Force,
            $msg = fmt("HTTP brute force: %s has %d auth failures against %s",
                       src, http_failures[src], c$id$resp_h),
            $src = src,
            $identifier = cat(src, "http_auth"),
            $suppress_for = 10min,
        ]);

        Log::write(BRUTE_FORCE_LOG, BruteForceInfo(
            $ts=network_time(), $src=src, $dst=c$id$resp_h,
            $service="http", $failures=http_failures[src]));
    }
}
```

---

## Script 6 — Beaconing Detection

**File:** `beaconing.zeek`

Tracks periodic outbound HTTP connections that may indicate C2 callback behavior.

```zeek
##! Beaconing / C2 Detection for Lab v1.0
##! Identifies periodic outbound HTTP callbacks
##! MITRE ATT&CK: T1071.001

module LabDetect;

export {
    redef enum Notice::Type += {
        HTTP_Beaconing,
        HTTP_Raw_IP_Request,
        Suspicious_TLS_Port,
    };

    ## Minimum callbacks to consider beaconing
    const beacon_min_requests: count = 20 &redef;

    ## Tracking window for beacon analysis
    const beacon_window: interval = 5min &redef;
}

## Track HTTP request timestamps per destination
type BeaconTracker: record {
    count_val:  count;
    first_seen: time;
    last_seen:  time;
};

global beacon_trackers: table[addr, addr] of BeaconTracker
    &create_expire=10min;

## Custom log
redef enum Log::ID += { BEACON_LOG };

type BeaconInfo: record {
    ts:             time        &log;
    src:            addr        &log;
    dst:            addr        &log;
    host:           string      &log;
    uri:            string      &log;
    user_agent:     string      &log &default="(none)";
    request_count:  count       &log;
    window_secs:    double      &log;
};

event zeek_init() {
    Log::create_stream(BEACON_LOG, [$columns=BeaconInfo, $path="lab-beaconing"]);
}

## Track HTTP requests for beaconing patterns
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # --- Raw IP request detection ---
    if ( c$http?$host ) {
        if ( /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ in c$http$host ) {
            NOTICE([
                $note = HTTP_Raw_IP_Request,
                $msg = fmt("HTTP request to raw IP %s from %s",
                           c$http$host, src),
                $conn = c,
                $identifier = cat(src, dst),
                $suppress_for = 10min,
            ]);
        }
    }

    # --- Beacon counting ---
    if ( [src, dst] !in beacon_trackers ) {
        beacon_trackers[src, dst] = BeaconTracker(
            $count_val=1,
            $first_seen=network_time(),
            $last_seen=network_time());
    } else {
        beacon_trackers[src, dst]$count_val += 1;
        beacon_trackers[src, dst]$last_seen = network_time();
    }

    local tracker = beacon_trackers[src, dst];

    if ( tracker$count_val == beacon_min_requests ) {
        local window = interval_to_double(tracker$last_seen - tracker$first_seen);

        NOTICE([
            $note = HTTP_Beaconing,
            $msg = fmt("Possible beaconing: %s -> %s (%d requests in %.0f seconds)",
                       src, dst, tracker$count_val, window),
            $conn = c,
            $identifier = cat(src, dst),
            $suppress_for = 15min,
        ]);

        Log::write(BEACON_LOG, BeaconInfo(
            $ts=network_time(), $src=src, $dst=dst,
            $host=c$http?$host ? c$http$host : cat(dst),
            $uri=original_URI,
            $user_agent=c$http?$user_agent ? c$http$user_agent : "(none)",
            $request_count=tracker$count_val,
            $window_secs=window));
    }
}

## Detect TLS on non-standard ports
event ssl_established(c: connection) {
    if ( c$id$resp_p != 443/tcp && c$id$resp_p != 8443/tcp ) {
        NOTICE([
            $note = Suspicious_TLS_Port,
            $msg = fmt("TLS connection on non-standard port %s: %s -> %s",
                       c$id$resp_p, c$id$orig_h, c$id$resp_h),
            $conn = c,
            $identifier = cat(c$id$orig_h, c$id$resp_h, c$id$resp_p),
            $suppress_for = 10min,
        ]);
    }
}
```

---

## Script 7 — Suspicious User-Agent Detection

**File:** `suspicious-ua.zeek`

Flags HTTP user-agents associated with reconnaissance tools, scripting libraries, and empty headers.

```zeek
##! Suspicious User-Agent Detection for Lab v1.0
##! Flags known attack tool user-agents in HTTP traffic
##! MITRE ATT&CK: T1071.001

module LabDetect;

export {
    redef enum Notice::Type += {
        Suspicious_User_Agent,
        Empty_User_Agent,
    };

    ## Known suspicious user-agent substrings (case-insensitive match)
    const suspicious_agents: set[string] = {
        "nmap",
        "nikto",
        "sqlmap",
        "dirbuster",
        "gobuster",
        "masscan",
        "wpscan",
        "burp",
        "zap",
        "openvas",
        "nessus",
        "metasploit",
        "hydra",
        "wfuzz",
        "ffuf",
        "nuclei",
        "whatweb",
    } &redef;

    ## User-agents that are noteworthy but not necessarily malicious
    const notable_agents: set[string] = {
        "python-requests",
        "python-urllib",
        "curl/",
        "wget/",
        "go-http-client",
        "java/",
        "powershell",
    } &redef;
}

## Custom log
redef enum Log::ID += { UA_LOG };

type UAInfo: record {
    ts:         time        &log;
    uid:        string      &log;
    src:        addr        &log;
    dst:        addr        &log;
    host:       string      &log;
    uri:        string      &log;
    user_agent: string      &log;
    severity:   string      &log;
};

event zeek_init() {
    Log::create_stream(UA_LOG, [$columns=UAInfo, $path="lab-suspicious-ua"]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( ! is_orig || to_lower(name) != "user-agent" )
        return;

    local ua_lower = to_lower(value);
    local src = c$id$orig_h;
    local host = c$http?$host ? c$http$host : cat(c$id$resp_h);
    local uri = c$http?$uri ? c$http$uri : "(unknown)";

    # --- Empty User-Agent ---
    if ( |value| == 0 ) {
        NOTICE([
            $note = Empty_User_Agent,
            $msg = fmt("Empty User-Agent from %s to %s", src, host),
            $conn = c,
            $identifier = cat(src, "empty_ua"),
            $suppress_for = 10min,
        ]);

        Log::write(UA_LOG, UAInfo(
            $ts=network_time(), $uid=c$uid, $src=src,
            $dst=c$id$resp_h, $host=host, $uri=uri,
            $user_agent="(empty)", $severity="medium"));
        return;
    }

    # --- Known malicious tools ---
    for ( agent in suspicious_agents ) {
        if ( agent in ua_lower ) {
            NOTICE([
                $note = Suspicious_User_Agent,
                $msg = fmt("Suspicious User-Agent '%s' from %s to %s",
                           value, src, host),
                $conn = c,
                $identifier = cat(src, agent),
                $suppress_for = 5min,
            ]);

            Log::write(UA_LOG, UAInfo(
                $ts=network_time(), $uid=c$uid, $src=src,
                $dst=c$id$resp_h, $host=host, $uri=uri,
                $user_agent=value, $severity="high"));
            return;
        }
    }

    # --- Notable scripting tools ---
    for ( agent in notable_agents ) {
        if ( agent in ua_lower ) {
            Log::write(UA_LOG, UAInfo(
                $ts=network_time(), $uid=c$uid, $src=src,
                $dst=c$id$resp_h, $host=host, $uri=uri,
                $user_agent=value, $severity="low"));
            return;
        }
    }
}
```

---

## Custom Log Files Created

After deployment, these additional log files will appear in `/nsm/zeek/logs/current/`:

| Log File | Source Script | Contents |
|----------|-------------|----------|
| `lab-exfil.log` | `http-exfil.zeek` | HTTP exfiltration events |
| `lab-dns-tunnel.log` | `dns-tunnel.zeek` | DNS tunneling indicators |
| `lab-web-attacks.log` | `web-attacks.zeek` | Web attack detections |
| `lab-brute-force.log` | `brute-force.zeek` | Auth failure tracking |
| `lab-beaconing.log` | `beaconing.zeek` | C2 beaconing events |
| `lab-suspicious-ua.log` | `suspicious-ua.zeek` | Suspicious user-agent log |

All detections also generate `notice.log` entries viewable in the Security Onion SOC UI.

---

## Verification Checklist

After deployment, verify the pack is working:

```bash
# 1. Check Zeek is running with no errors
sudo so-zeek-status

# 2. Verify scripts loaded
grep "lab-v1" /nsm/zeek/logs/current/loaded_scripts.log

# 3. Check for new log files
ls -la /nsm/zeek/logs/current/lab-*.log

# 4. Monitor notices in real-time
tail -f /nsm/zeek/logs/current/notice.log | grep "LabDetect"

# 5. Run a test (from Kali Linux) — should trigger suspicious UA
curl -A "Nikto/2.1" http://<target-ip>/

# 6. Verify the alert appeared
cat /nsm/zeek/logs/current/lab-suspicious-ua.log
```

---

*Lab v1.0 — Joseph Asante — SOC Lab Detection Engineering*
