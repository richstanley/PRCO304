#!/usr/bin/env python3

# Import Modules
import tkinter as tk
from tkinter import *
from tkinter import ttk
from PIL import ImageTk,Image
import threading
import socket
import subprocess
import sys
from datetime import datetime
import ipaddress
import multiprocessing
import os
import scapy.all as scapy
import argparse
from scapy.layers import http

# Variables
Title = ("Arial", 24)


class PyScan(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        # tk.Tk.iconbitmap(self, default="image.ico")
        tk.Tk.wm_title(self, "PyScan")

        # Sets Application size to monitor resolution
        #screen_width = self.winfo_screenwidth()
        #screen_height = self.winfo_screenheight()
        #self.geometry("%dx%d+0+0" % (screen_width, screen_height))
        self.geometry("800x600")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # Place frames (pages) in container
        for F in (HomePage, PortScanPage, PingSweepPage, PacketSniffPage, WiFiPage, LearningPage, LegalPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(HomePage)

    # Show frame (page) in application when selected
    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()


class HomePage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="PyScan", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        def homeText():
            homeText = "HomeText.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(homeText).read())

        lblOutput = tk.Label(self, bg='white', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)

        homeText()


class PortScanPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Port Scan", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        def portScan():

            # Retrieve IP address from entry box - validate input before proceeding
            while True:
                try:
                    targetHostIp = (ipaddress.ip_address(getInput()))
                    break
                except ValueError:
                    print("Please enter a valid IPv4 or IPv6 address")
                    sys.exit()

            formattedIp = str(targetHostIp)
            socket.gethostbyname(formattedIp)

            # Scan Start Time
            startTime = datetime.now()

            # Write strings to text file (start time, target name/ip, open ports)
            with open("PortScanResults.txt", "a") as f:
                f.write("Start Time: {}\n".format(startTime))
                f.write("target: {}\n\n".format(formattedIp))
                f.write("Open Ports: \n")
                f.write("-" * 11)
                f.write("\n")
                f.close()

            print("Scanning Target for open ports...", formattedIp)

            # Check if each port within range is open - if open, write to file
            try:
                for port in range(1, 65536):
                    scanSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = scanSock.connect_ex((formattedIp, port))
                    if result == 0:
                        with open("PortScanResults.txt", "a") as f:
                            f.write("Port {} \n".format(port))
                            f.close()
                    scanSock.close()

            # Print message if program stopped with keyboard command (Ctrl+C)
            except KeyboardInterrupt:
                print("Cancelling... (Ctrl+C)")
                sys.exit()

            # Print message if target not found
            except socket.gaierror:
                print('Exiting... (Target not found)')
                sys.exit()

            # Scan End Time
            endTime = datetime.now()

            # Scan Duration
            duration = endTime - startTime

            # Write strings to text file (End time, Duration, Divider)
            with open("PortScanResults.txt", "a") as f:
                f.write("\n\nEnd Time: {}\n".format(endTime))
                f.write("Duration: {}".format(duration))
                f.write("\n")
                f.write("-" * 68)
                f.write("\n")
                f.close()

            # Read results to text file
            portScanResults = "PortScanResults.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(portScanResults).read())

        # Retrieve user input
        def getInput():
            targetHost = entInput.get()
            return targetHost

        # Page objects
        lblOutput = tk.Label(self, bg='white', relief='ridge', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        lblMessage = tk.Label(self, bg='white', text="Enter an IP Address: ")
        lblMessage.place(relx=0.4, rely=0.85, relwidth=0.3, relheight=0.07)

        lblExample = tk.Label(self, bg='white', text="E.g. 192.168.32.128 ")
        lblExample.place(relx=0.4, rely=0.935, relwidth=0.3, relheight=0.07)

        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        entInput = tk.Entry(self, font=40, bd=2)
        entInput.place(relx=0.4, rely=0.9, relwidth=0.3, relheight=0.05)

        btnEnter = tk.Button(self, text="Scan", bg='white', fg='black', bd=2, command=threading.Thread(target=portScan).start)
        btnEnter.place(relx=0.7, rely=0.9, relwidth=0.1, relheight=0.05)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)


class PingSweepPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Ping Sweep", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        def pingSweepScript():

            # Function to scan subnet - once entire subnet is scanned, the process will end
            def pingSweep(job_q, results_q):

                Devnull = open(os.devnull, 'w')

                while True:
                    ip = job_q.get()
                    if ip is None:
                        break
                    try:
                        subprocess.check_call(['ping', '-c1', ip], stdout=Devnull)
                        results_q.put(ip)
                    except:
                        pass

            if __name__ == '__main__':
                pool_size = 255

                jobs = multiprocessing.Queue()
                results = multiprocessing.Queue()

                # Retrieve and validate user input
                while True:
                    try:
                        targetIp = (ipaddress.ip_address(getInput()))
                        break
                    except ValueError:
                        print("Please enter a valid IPv4 or IPv6 address")
                        sys.exit()

                targetIpStr = str(targetIp)
                # Remove last octet of IP Address (so subnet can be scanned)
                formattedIp = '.'.join(targetIpStr.split('.')[0:-1])

                startTime = datetime.now()

                with open("PingSweepResults.txt", "a") as f:
                    f.write("Start Time: {}\n".format(startTime))
                    f.write("target: {}\n\n".format(targetIpStr))
                    f.write("Active Hosts: \n")
                    f.write("-" * 14)
                    f.write("\n")
                    f.close()

                # Conducts scan of subnet via multiprocessing (allowing multiple addresses to be scanned simultaneously)
                pool = [multiprocessing.Process(target=pingSweep, args=(jobs, results)) for i in range(pool_size)]
                for p in pool:
                    p.start()

                for i in range(1, 255):
                    jobs.put(formattedIp + '.{0}'.format(i))

                for p in pool:
                    jobs.put(None)

                for p in pool:
                    p.join()

                # Write active hosts to results file
                while not results.empty():
                    ip = results.get()
                    with open("PingSweepResults.txt", "a") as f:
                        f.write(ip + "\n")
                        f.close()

                # Scan End Time
                endTime = datetime.now()

                # Scan Duration
                duration = endTime - startTime

                # Write strings to text file (End time, Duration, Divider)
                with open("PingSweepResults.txt", "a") as f:
                    f.write("\n\nEnd Time: {}\n".format(endTime))
                    f.write("Duration: {}".format(duration))
                    f.write("\n")
                    f.write("-" * 68)
                    f.write("\n")
                    f.close()

            # Read results from text file
            pingSweepResults = "PingSweepResults.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(pingSweepResults).read())

        # Retrieve user input
        def getInput():
            targetHost = entInput.get()
            return targetHost

        # Page Objects
        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        lblMessage = tk.Label(self, bg='white', text="Enter an IP Address: ")
        lblMessage.place(relx=0.4, rely=0.85, relwidth=0.3, relheight=0.07)

        lblExample = tk.Label(self, bg='white', text="E.g. 192.168.32.128 ")
        lblExample.place(relx=0.4, rely=0.935, relwidth=0.3, relheight=0.07)

        lblOutput = tk.Label(self, bg='white', relief='ridge', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        entInput = tk.Entry(self, font=40, bd=2)
        entInput.place(relx=0.4, rely=0.9, relwidth=0.3, relheight=0.05)

        btnEnter = tk.Button(self, text="Scan", bg='white', fg='black', bd=2,
                             command=threading.Thread(target=pingSweepScript).start)
        btnEnter.place(relx=0.7, rely=0.9, relwidth=0.1, relheight=0.05)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)


class PacketSniffPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Packet Sniffing", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        def packetSniff():

            # Re-open application as subprocess in root mode if not in root already - necessary as scan requires root privileges
            if os.getuid() == 0:
                print("Root mode")
            else:
                print("Not in root mode")
                subprocess.call(['sudo', 'python3', *sys.argv])

            # Interface to sniff
            def interface():
                parser = argparse.ArgumentParser()
                parser.add_argument("-i", "--interface", dest="interface", help="Specify interface to sniff")
                arguments = parser.parse_args()
                return arguments.interface

            # Sniff interface using scapy - applies prn to each packet
            def sniffing(iface):
                scapy.sniff(iface=iface, store=False, prn=analysis)

            # Function that is applied to each packet
            def analysis(packet):
                if packet.haslayer(http.HTTPRequest):
                    with open("packetSniffResults.txt", "a") as f:
                        f.write(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path + "\n")
                        f.close()
                    if packet.haslayer(scapy.Raw):
                        load = packet[scapy.Raw].load
                        keys = ["username", "password", "pass", "email"]
                        for key in keys:
                            if key in load:
                                with open("packetSniffResults.txt", "a") as f:
                                    f.write("Potential User Credentials: " + load)
                                    f.close()
                            break

            iface = interface()
            sniffing(iface)

        # Displays results of packet sniffing (linked to button press)
        def packetSniffResults():
            storedWifiPasswords = "packetSniffResults.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(storedWifiPasswords).read())

        # Page objects
        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        lblOutput = tk.Label(self, bg='white', relief='ridge', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        btnEnter = tk.Button(self, text="Scan", bg='white', fg='black', bd=2, command=threading.Thread(target=packetSniff).start)
        btnEnter.place(relx=0.49, rely=0.9, relwidth=0.1, relheight=0.05)

        btnResults = tk.Button(self, text="Results", bg='white', fg='black', bd=2, command=packetSniffResults)
        btnResults.place(relx=0.61, rely=0.9, relwidth=0.1, relheight=0.05)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)


# WINDOWS MACHINES ONLY (Uses 'netsh' command)
class WiFiPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Wi-Fi Passwords", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        def wifiPass():
            # Runs specified commands
            data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
            # i is set to the value (ssid) following proceeding the colon after the "All User Profile" string
            ssid = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]

            # Checks for the key (password) of the network for each ssid profile saved on the device, and writes results to file
            for i in ssid:
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode(
                    'utf-8').split('\n')
                output = [b.split(":")[1][1:-1] for b in output if "Key Content" in b]
                try:
                    with open("WifiPasswords.txt", "a") as f:
                        f.write("{:<30}|  {:<} \n".format(i, output[0]))
                        f.close()
                except IndexError:
                    with open("WifiPasswords.txt", "a") as f:
                        f.write("{:<30}|  {:<} \n".format(i, "--No password found--"))
                        f.close()
            input("")

        # Display results of scan (linked to button press)
        def wifiPassResults():
            storedWifiPasswords = "wifiPasswords.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(storedWifiPasswords).read())

        # Page Objects
        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        lblOutput = tk.Label(self, bg='white', relief='ridge', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        lblMessage = tk.Label(self, bg='white', text="NOTE: Windows machines only")
        lblMessage.place(relx=0.4, rely=0.85, relwidth=0.4, relheight=0.07)

        lblExample = tk.Label(self, bg='white', text="Click Results ~5 seconds after the scan ")
        lblExample.place(relx=0.4, rely=0.935, relwidth=0.4, relheight=0.07)

        btnEnter = tk.Button(self, text="Scan", bg='white', fg='black', bd=2, command=threading.Thread
        (target=wifiPass).start)
        btnEnter.place(relx=0.49, rely=0.9, relwidth=0.1, relheight=0.05)

        btnResults = tk.Button(self, text="Results", bg='white', fg='black', bd=2, command=wifiPassResults)
        btnResults.place(relx=0.61, rely=0.9, relwidth=0.1, relheight=0.05)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)


class LearningPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Learning", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        # Display information on page
        def LearningText():
            learningText = "LearningText.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(learningText).read())

        # Page Objects
        lblOutput = tk.Label(self, bg='white', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)

        LearningText()


class LegalPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Legal", bg='white', font=Title)
        label.place(relx=0.45, rely=0.04)

        self['bg'] = 'white'

        # Display information on page
        def LegalText():
            legalText = "LegalText.txt"
            T = Text(lblOutput, state='normal', fg='black')
            T.pack()
            T.insert(END, open(legalText).read())

        # Page Objects
        lblOutput = tk.Label(self, bg='white', bd=2)
        lblOutput.place(relx=0.25, rely=0.15, relwidth=0.7, relheight=0.7)

        frameSideBorder = tk.Frame(self, bg='black', bd=1)
        frameSideBorder.place(relx=-0.01, rely=0, relwidth=0.2, relheight=1)

        frameSideInner = tk.Frame(self, bg='#0E4d92')
        frameSideInner.place(relx=-0.01, rely=0, relwidth=0.199, relheight=1)

        # Sidebar buttons
        btnHomePage = tk.Button(self, text="Home", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(HomePage))
        btnHomePage.place(relx=0.02, rely=0.18, relwidth=0.15, relheight=0.05)

        btnLearningPage = tk.Button(self, text="Learning", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(LearningPage))
        btnLearningPage.place(relx=0.02, rely=0.29, relwidth=0.15, relheight=0.05)

        btnPortScanPage = tk.Button(self, text="Port Scan", bg='#1C86EE', fg='white',
                                    command=lambda: controller.show_frame(PortScanPage))
        btnPortScanPage.place(relx=0.02, rely=0.41, relwidth=0.15, relheight=0.05)

        btnPingSweepPage = tk.Button(self, text="Ping Sweep", bg='#1C86EE', fg='white',
                                     command=lambda: controller.show_frame(PingSweepPage))
        btnPingSweepPage.place(relx=0.02, rely=0.49, relwidth=0.15, relheight=0.05)

        btnPacketSniffPage = tk.Button(self, text="Packet Sniffing", bg='#1C86EE', fg='white',
                                       command=lambda: controller.show_frame(PacketSniffPage))
        btnPacketSniffPage.place(relx=0.02, rely=0.57, relwidth=0.15, relheight=0.05)

        btnWiFiPage = tk.Button(self, text="WiFi Passwords", bg='#1C86EE', fg='white',
                                command=lambda: controller.show_frame(WiFiPage))
        btnWiFiPage.place(relx=0.02, rely=0.65, relwidth=0.15, relheight=0.05)

        btnLegalPage = tk.Button(self, text="Legal", bg='#1C86EE', fg='white',
                                 command=lambda: controller.show_frame(LegalPage))
        btnLegalPage.place(relx=0.02, rely=0.77, relwidth=0.15, relheight=0.05)

        LegalText()


# Runs application in a continuous loop (so it stays open), until closed by the user
app = PyScan()
app.mainloop()
