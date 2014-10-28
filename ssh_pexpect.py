#!/usr/bin/python
import pexpect
import sys
import time
user = "root"
password = "toor"
target = "172.16.139.129"
logged_in = 0
thetimeout = 10
commands=("w","ls -al","who","ps -ef")
def run_commands(kid,prompt,):
	command_count = 0
	kid.logout = sys.stdout
	prompt_ret = 0
	print "p",prompt
	while command_count < (len(commands)) and prompt_ret == 0:
		print "Running command ", commands[command_count]
#	for command in commands:
		kid.sendline(" "+commands[command_count]+'; echo -=-\n')
		print " "+commands[command_count]+'; echo -=-\n'
		prompt_ret = child.expect_exact([prompt,pexpect.EOF,pexpect.TIMEOUT])
		if prompt_ret == 0:
			print commands[command_count]," DATA\n ",kid.before
		command_count += 1 


print commands
child = pexpect.spawn("ssh -v "+user+"@"+target+" /bin/sh",timeout = thetimeout)
child.logout = sys.stdout
while logged_in == 0:
	index = child.expect(['.assword:*', 'Are you sure you want to continue connecting*', pexpect.EOF, pexpect.TIMEOUT])
	if index == 0:
		child.sendline(password +'\necho $_\n')
		logged_in = 1
		r = child.expect_exact(['$','#','/bin/sh',pexpect.EOF, pexpect.TIMEOUT])
		prompt = child.after
		print prompt
		if r == 1:
			print "Root!"
		if r == 0 or r == 1:
			run_commands(child,prompt.split(':')[0])
		elif r == 2:
			child.sendline(" echo -=-\n")
			run_commands(child,"-=-")

	elif index == 1:
		child.sendline('yes\n')
		print "yes I'm sure"
	else:
		print "damn"
		child.interact()
		
print "out of while"
child.kill(9)
