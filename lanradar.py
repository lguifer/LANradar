import argparse
import nmap
import ipaddress
import os
import time
from datetime import datetime
import signal
import sys
import pdb
import subprocess

# Function to handle SIGINT (CTRL+C)
def handle_ctrl_c(signum, frame):
	print("\nExiting the script gracefully...")
	# Perform necessary cleanup or shutdown actions here
	sys.exit(0)

# Assign the signal handler function to SIGINT
signal.signal(signal.SIGINT, handle_ctrl_c)

def get_arguments():
	parser = argparse.ArgumentParser(description="LAN scan to detect new MACs.")
	parser.add_argument("--lan", required=True, help="LAN IP range in XXX.XXX.XXX.XXX/XX format")
	parser.add_argument("--time", required=True, help="Time interval for scans in seconds.")
	parser.add_argument("--domain", help="Specify the domain name of the machines (optional)")
	parser.add_argument("--log", help="IP of the server to send logs to (optional)")
	return parser.parse_args()

def send_log_to_server(line, server_ip):
	if server_ip:
		command = f"echo -n 'host_name LANradar[1]: {line}' | ncat -t {server_ip} 514"
		# print(command)
		os.system(command)

def get_current_time():
	# Get the current time as a timestamp
	timestamp = time.time()
	# Convert the timestamp to a datetime object
	datetime_object = datetime.fromtimestamp(timestamp)
	# Format the datetime object as a string in DD/MM/YYYY HH:MM:SS format
	formatted_time = datetime_object.strftime('%d/%m/%Y %H:%M:%S')
	return formatted_time

def clear_console():
	os.system('clear')

def get_lan_range():
	lan_range = input("Enter your LAN range (XXX.XXX.XXX.XXX/XX): ")
	return lan_range

def get_scan_interval():
	return int(input("Enter the scan interval in seconds: "))

def scan_lan(lan_range):
	nm = nmap.PortScanner()
	print(f"Running nmap for range {lan_range}")
	nm.scan(hosts=lan_range, arguments='-sn')
	print(f"nmap completed the scan. Hosts found: {nm.all_hosts()}")
	found_macs = []
	for host in nm.all_hosts():
		if 'mac' in nm[host]['addresses']:
			mac = nm[host]['addresses']['mac']
			ip = nm[host]['addresses']['ipv4']
			name = nm[host]['hostnames'][0]['name']
			found_macs.append((mac, ip, name))
	print(f"MACs found: {found_macs}")
	return found_macs

def is_mac_registered(mac):
	# Check if the MAC exists in the 'registered_macs.txt' file
	if os.path.exists("registered_macs.txt"):
		with open("registered_macs.txt", "r") as file:
			for line in file:
				if mac == line.strip().split()[0]:  # Assume MAC is the first field in each line
					return True
	else:
		with open("registered_macs.txt", "w") as file:
			file.close()
	return False

def compare_macs(found_macs):
	unauthorized_macs = []
	for mac, ip, name in found_macs:
		if not is_mac_registered(mac):
			if name == "":
				name = "unknown"
			unauthorized_macs.append((mac, ip, name))
	return unauthorized_macs

def load_registered_macs():
	registered_macs = set()
	if os.path.exists("registered_macs.txt"):
		with open("registered_macs.txt", "r") as file:
			for line in file:
				mac = line.strip().split()[0]
				registered_macs.add(mac)
	print(f"Registered MACs: {registered_macs}")
	return registered_macs

def main():
	args = get_arguments()
	lan_range = args.lan
	server_ip = args.log
	interval = args.time
	domain = args.domain
	registered_macs = load_registered_macs()  # Load registered MACs at the start

	while True:
		clear_console()
		print("Performing scan...")
		found_macs = scan_lan(lan_range)
		new_macs = compare_macs(found_macs)

		# Open the file once and write all new MACs if needed
		with open("registered_macs.txt", "a") as mac_file:
			for mac, ip, name in new_macs:
				if mac not in registered_macs:
					mac_file.write(f"{mac} {name}\n")
					registered_macs.add(mac)  # Add the new MAC to avoid duplicates in this run

		# Log unauthorized MACs to the log file
		try:
			with open("/var/log/check-macs/unauthorized.log", "a") as log_file:
				for mac, ip, name in new_macs:
					line = f"New unauthorized MAC found: {mac} with associated IP: {ip} and hostname: {name}"
					print(line)  # Debugging: Display the line in the console
					log_file.write(line + "\n")
					# Send the information via syslog using NCAT
					if server_ip:
						send_log_to_server(line, server_ip)
			print("File writing completed")
		except Exception as e:
			print(f"Error writing to file: {e}")

		print("Waiting for the next scan...")
		time.sleep(int(interval))

if __name__ == "__main__":
	main()
