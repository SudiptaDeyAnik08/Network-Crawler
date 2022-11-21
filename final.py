import socket
import os, subprocess
import nmap
import re
import scanner
import dns
import dns.resolver
import requests
import sys


##########################################################################
			# IP Address Conversion 
			# Converting the ip address and DNS
			# Step-1 and Step-2
##########################################################################


web_address = input("Please enter IP address / website address:\n")
# If condition statrting here for checking the top level domain name (TLD)

if( web_address.find(".us")  != -1 or 
web_address.find(".com")  != -1 or
web_address.find(".net") != -1 or 
web_address.find(".org")  != -1 or 
web_address.find(".top")  != -1 or 
web_address.find(".gov")  != -1 or 
web_address.find(".mill")  != -1 or 
web_address.find(".io")  != -1 or 
web_address.find(".edu")  != -1 or 
web_address.find(".bd") != -1):

 print("found")
 ipAddress = socket.gethostbyname(web_address)
 print(f'The {web_address} IP Address is {socket.gethostbyname(web_address)}')
else:
 # Finding hostname from IP address
 try: 
  print(socket.gethostbyaddr(web_address))
 except:
  print("Can not able to access though the ip address")

# If condition ending here



##########################################################################
			# IP Address  Validation 
			# Range Of IP port open/not
			# Step-1 and Step-2
##########################################################################

# Regular Expression Pattern to recognise IPv4 addresses.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535

#Creating an array for storing the ports
open_ports = []

validity_of_ip_address = 0

while True:
    print("web_address : ",web_address )
    ip_add_entered = ipAddress
    print("\n\n\n\n")
    print("###############################################")
    print("# Checking the validity of the Web/IP Address #")
    print("###############################################\n\n")
    if ip_add_pattern.search(ip_add_entered):
        #validity_of_ip_address = true goto line 65
        print(f"{ip_add_entered} is a valid ip address\n\n")
        break
    else :
    	validity_of_ip_address = -1
    	print("Invalid Ip Address. Enter a valid Ip")    

#Scanning the reange of ports
while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning 
    # all the ports is not advised.
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

valid_port_number = []

nm = nmap.PortScanner()
# We're looping over all of the ports in the specified range.
for port in range(port_min, port_max + 1):
    try:
        # The result is quite interesting to look at. You may want to inspect the dictionary it returns. 
        # It contains what was sent to the command line in addition to the port status we're after. 
        # For in nmap for port 80 and ip 10.0.0.2 you'd run: nmap -oX - -p 89 -sV 10.0.0.2
        result = nm.scan(ip_add_entered, str(port))
        # Uncomment following line and look at dictionary
        # print(result)
        # We extract the port status from the returned object
        port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
        print(f"Port {port} is {port_status}")
        if(port_status == "open"):
        	valid_port_number.append(port)
    except:
        # We cannot scan some ports and this ensures the program doesn't crash when we try to scan them.
        print(f"Cannot scan port {port}.")


##########################################################################
			# Find DNS Resolver
			# Step-3
##########################################################################




# use this webaddress for test hashnode.com


#  Finding A Records
result = dns.resolver.resolve(web_address, 'A')
A_records = []

for IPval in result:
    A_records.append(IPval.to_text())
print("A Records are ", A_records)


#Finding CNAME Values
print("\n\n\n\n")
CNAME_Value = 'a'
try:
	result_Cname = dns.resolver.resolve('mail.'+web_address, 'CNAME')
	CNAME_Value = result_Cname
	
	for cnameval in result_Cname:
		print('CNAME Target Address:', cnameval.target)
except: 
	print("CNAME Target Address: Error")
	CNAME_Value = "CNAME Target Address: Error"

	
# 🔹 Finding MX Records
MX_record = []
print("\n\n\n\n")
result = dns.resolver.resolve(web_address, 'MX')

for exdata in result:
    print('MX Record: ',exdata)
    MX_record.append(exdata)

##########################################################################
			# Find Subdomain 
			# you can change the wordlist 
			# Step-4
##########################################################################
print("\n\n\n\n")   

sub = open('ab.txt').read()
subs = sub.splitlines()

valid_url = []
a=0;
for s in subs:
	url = "https://{}.{}".format(s,web_address)
	print(url)
	try:
		requests.get(url)
	except Exception as ex:
		pass
	else:
		print("valid",url)
		valid_url.append(url)

print("\n\n\n\n")

print("Valid Subdomain: ", valid_url)   


##########################################################################
			# Final Summarry Result
##########################################################################

print("\n\n\n\n")


print("###############################################")
print("# 					     #")
print("# 	     Summary Of Findings      	     #")
print("# 					     #")
print("###############################################\n\n")

print("## 1. Checking the validity of the Web/IP Address #")
print("\n")
if(validity_of_ip_address == 0):
	ip_add_entered = ipAddress
	print(f"{web_address} / {ip_add_entered} is a valid Ip/Web Address")
else:
	print("Invalid Ip/ Web Address")


print('\n## 2. Opne Ports: \n')
print("Open Port: ", valid_port_number)
print('\n')


for i in range(len(valid_port_number)):
	print(f"Port {valid_port_number[i]} is Open")
print('\n')


print('## 3. A Records are :  ')
for i in range(len(A_records)):
	print(f"Ip Address{[i]}:  {A_records[i]} ")

print('\n')
print('## 4. CNAME: ')
print('CNAME Target Address: ', CNAME_Value)


print('\n')
print('## 5. MX Record : ')
for i in range(len(MX_record)):
	print(f"MX Record {[i]} :  {MX_record[i]} ")


print('\n')
print('## 6. Valid Sub-Domain: ')
for i in range(len(valid_url)):
	print(f"Valid Sub Domain is :  {valid_url[i]} ")

print('\n')
print('\n')
print("#############################################################")
print("# Tool Version: V.1, GUI version work is under construction #")
print("#      This tool is Developed by Sudipta Dey Anik,          #")
print("#     Under the supervion of Md. Jahangir Alam,CISA         #")
print("#############################################################")
