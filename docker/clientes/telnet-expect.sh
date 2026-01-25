#!/usr/bin/expect
# telnet-expect.sh "lalala" "192.168.0.111" "2222"
set timeout 1
set host [lindex $argv 0]
set port [lindex $argv 1]

spawn telnet $host $port
expect "*login:" { send "\x18" }
