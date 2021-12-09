from CSVPacket import Packet, CSVPackets
import sys

IPProtos = [0 for x in range(256)]
numBytes = 0
numPackets = 0

csvfile = open(sys.argv[1],'r')

# Create array for TCP and UDP
TCP = [0 for y in range(1025)]
UDP = [0 for z in range(1025)]

# Create array for IP address & user count
IP = [0 for x in range(0)]
user = [0 for x in range(0)]

# Create array for question 6
GIP = [0 for x in range(0)]
Guser = [0 for x in range(0)]
IIP = [0 for x in range(0)]
Iuser = [0 for x in range(0)]
OIP = [0 for x in range(0)]
Ouser = [0 for x in range(0)]

# Create a dictionary for connection
conn1 = dict()
conn2 = dict()
s_tcp = "tcp/"
s_udp = "udp/"


for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    #print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1

    #check for UDP & TCP
    if ((proto == 6) or (proto == 17)):
        if (proto == 6):
            if (pkt.tcpdport <= 1024):
                # Part of Question 9 from here
                str_tcp = s_tcp + str(pkt.tcpdport)
                if (pkt.ipdst not in conn1):
                    str1 = set([pkt.ipsrc + str_tcp])
                    str2 = set([str_tcp])
                    conn2[pkt.ipdst] = (str1)
                    conn1[pkt.ipdst] = (str2)
                else:
                    conn2[pkt.ipdst].add(pkt.ipsrc + str_tcp)
                    conn1[pkt.ipdst].add(str_tcp)
                # Question 1 Code part
                TCP[pkt.tcpdport] += 1

        elif (proto == 17):
            if (pkt.udpdport <=1024):
                # Part of Question 9 from here
                str_udp = s_udp + str(pkt.udpdport)
                if (pkt.ipdst not in conn1):
                    str1 = set([pkt.ipsrc + str_udp])
                    str2 = set([str_udp])
                    conn2[pkt.ipdst] = (str1)
                    conn1[pkt.ipdst] = (str2)
                else:
                    conn2[pkt.ipdst].add(pkt.ipsrc + str_udp)
                    conn1[pkt.ipdst].add(str_udp)
                # Question 1 Code part
                UDP[pkt.udpdport] += 1
                
    # GRE
    if (proto == 47):
        i = 0
        
        # Check to see if IP address is on it
        if (pkt.ipdst not in GIP):
            GIP.append(pkt.ipdst)
            Guser.append(1)
        else:
            i = GIP.index(pkt.ipdst)
            Guser[i] += 1

        if (pkt.ipsrc not in GIP):
            GIP.append(pkt.ipsrc)
            Guser.append(1)
        else:
            i = GIP.index(pkt.ipsrc)
            Guser[i] += 1
    
    # IPSEC
    if (proto == 50 or proto == 51):
        i = 0
        
        # Check to see if IP address is on it
        if (pkt.ipdst not in IIP):
            IIP.append(pkt.ipdst)
            Iuser.append(1)
        else:
            i = IIP.index(pkt.ipdst)
            Iuser[i] += 1

        if (pkt.ipsrc not in IIP):
            IIP.append(pkt.ipsrc)
            Iuser.append(1)
        else:
            i = IIP.index(pkt.ipsrc)
            Iuser[i] += 1
        
    # OSPF
    if (proto == 89):
        k = 0
        
        # Check to see if IP address is on it
        if (pkt.ipdst not in OIP):
            OIP.append(pkt.ipdst)
            Ouser.append(1)
        else:
            k = OIP.index(pkt.ipdst)
            Ouser[k] += 1

        if (pkt.ipsrc not in OIP):
            OIP.append(pkt.ipsrc)
            Ouser.append(1)
        else:
            k = OIP.index(pkt.ipsrc)
            Ouser[k] += 1
    
    #get IP address & User amount
    i = 0
        
    # Check to see if IP address is on it
    if (pkt.ipdst not in IP):
        IP.append(pkt.ipdst)
        user.append(1)
    else:
        i = IP.index(pkt.ipdst)
        user[i] += 1

    if (pkt.ipsrc not in IP):
        IP.append(pkt.ipsrc)
        user.append(1)
    else:
        i = IP.index(pkt.ipsrc)
        user[i] += 1

    
if ((len(sys.argv)) == 3):
    # Question 1: Extend the command to -stat to print TCP and UDP
    #             (Only print out if -stats is presented)
    if (sys.argv[2] == "-stats"):
        print("----------------------------------")
        print("TCP Port(s) Stat: ")
        for i in range(1025):
            if (TCP[i] != 0):
                print "Port No. : %3u   -   Amount: %9u" % (i, TCP[i])

        print("----------------------------------")
        print("UDP Port(s) Stat: ")
        for j in range(1025):
            if (UDP[j] != 0):
                print "Port No. : %3u   -   Amount: %9u" % (j, UDP[j])
        print("----------------------------------\n")


    # Question 3: Print out the cmd "-countip"
    #             (Only print out if -countip is presented)
    if (sys.argv[2] == "-countip"):
   
        # Get the list in dictionary
        list_dict = dict(zip(IP, user))
        sort_dict = sorted(list_dict.items(), reverse = True, key = lambda kv:(kv[1], kv[0]))
     
        # Print out the statement
        print("----------------------------------")
        print("[IP Address, User Amount]")
        for x in sort_dict:
            print(x)
        print("----------------------------------\n")
        
    # Question 9 & 10
    if (sys.argv[2] == "-connto"):
        # Create a counter
        counter = 0
    
        print("----------------------------------")
        conns = sorted(conn2.items(), reverse = True, key = lambda kv:(kv[1], kv[0]))
        for x,y in conns:
            print "IP Destination: %s  -  Number of Unique Source IP: %u, \n On Port: %s" % (x, len(y), conn1[x])
            counter += 1
            
            if (counter == 20):
                break
        print("----------------------------------\n")


if ((len(sys.argv)) == 4):
    if (sys.argv[3] == "-other"):
        # Get the list in dictionary of GRE, IPSEC, OSPF
        Gd = dict(zip(GIP, Guser))
        sort_Gd = sorted(Gd.items(), reverse = True, key = lambda kv:(kv[1], kv[0]))
                
        Id = dict(zip(IIP, Iuser))
        sort_Id = sorted(Id.items(), reverse = True, key = lambda kv:(kv[1], kv[0]))
                
        Od = dict(zip(OIP, Ouser))
        sort_Od = sorted(Od.items(), reverse = True, key = lambda kv:(kv[1], kv[0]))
                
        # Question 6: Print out the extra of cmd
        print("----------------------------------")
        print("[GRE:  IP Address, User Amount]")
        for x in sort_Gd:
            print(x)
        print("----------------------------------")
        print("[IPSEC:  IP Address, User Amount]")
        for y in sort_Id:
            print(y)
        print("----------------------------------")
        print("[OSPF:  IP Address, User Amount]")
        for z in sort_Od:
            print(z)
        print("----------------------------------\n")


# Original Print Statement
print "numPackets:%u numBytes:%u" % (numPackets,numBytes)
for i in range(256):
    if IPProtos[i] != 0:
        print "%3u: %9u" % (i, IPProtos[i])

