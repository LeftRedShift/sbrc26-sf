#!/usr/bin/expect
# ssh-expect.sh "lalala" "192.168.0.111" "2222"
set timeout 1
set username [lindex $argv 0]
set host [lindex $argv 1]
set port [lindex $argv 2]

spawn ssh $username@$host -p $port
expect "password:" { send "\x18" }
expect "Are you sure you want to continue connecting" { send "no\n" }