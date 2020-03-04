#!/usr/bin/env python

#Import Modules
import socket
import subprocess
import sys
from datetime import datetime

#Clear screen
subprocess.call('clear', shell=True) #Use shell=False (True = security hazard)

#Retrieve target to scan (User input)
targetHost = raw_input("Please enter a hostname or IP address to scan: ")
targetHostIp = socket.gethostbyname(targetHost)

print "Scanning Target for open ports...", targetHostIp

#Scan Start Time
startTime = datetime.now()

#Error Handling
try:
	for port in range(1,65536):
		scanSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = scanSock.connect_ex((targetHostIp, port))
		if result == 0:
			print "Port {}:	 Open".format(port)
		scanSock.close()

#Print message if program stopped with keyboard command (Ctrl+C)
except KeyboardInterrupt:
	print "Cancelling... (Ctrl+C)"
	sys.exit()

#Print message if target not found
except socket.gaierror:
	print 'Exiting... (Target not found)'
	sys.exit()

#Scan End Time
endTime = datetime.now()

#Scan Duration
duration = endTime - startTime

#Scan results
print 'Scan Completed!'
print 'Scan Duration: ', duration
 
