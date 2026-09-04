/** Small embedded sample so the analyzer can be tried without a log file. */
export const SAMPLE_LOG = `Jan  5 09:01:12 prod-web-1 sshd[2040]: Invalid user admin from 203.0.113.7 port 51200
Jan  5 09:01:12 prod-web-1 sshd[2040]: Connection closed by invalid user admin 203.0.113.7 port 51200 [preauth]
Jan  5 09:02:31 prod-web-1 sshd[2051]: Failed password for invalid user test from 203.0.113.7 port 51244 ssh2
Jan  5 09:02:33 prod-web-1 sshd[2052]: Failed password for invalid user guest from 203.0.113.7 port 51250 ssh2
Jan  5 09:04:11 prod-web-1 sshd[2077]: Failed password for root from 198.51.100.23 port 41120 ssh2
Jan  5 09:04:14 prod-web-1 sshd[2078]: Failed password for root from 198.51.100.23 port 41124 ssh2
Jan  5 09:04:18 prod-web-1 sshd[2079]: Failed password for root from 198.51.100.23 port 41129 ssh2
Jan  5 09:04:25 prod-web-1 sshd[2080]: Accepted password for root from 198.51.100.23 port 41130 ssh2
Jan  5 09:05:00 prod-web-1 sshd[2090]: Accepted publickey for alice from 192.0.2.10 port 52200 ssh2
Jan  5 09:06:40 prod-web-1 sshd[2101]: Failed password for deploy from 2001:db8::42 port 38000 ssh2`;
