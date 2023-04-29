from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    # Make a dummy header with a 0 checksum
    myChecksum = 0
    myID = os.getpid() & 0xffff  # Return the current process i
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)
    
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
 
            #Fill in start
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    #Fill in start
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": "*", "Hostname": "*", "Response Code": "timeout"}, ignore_index=True)
                    #print (df)
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    #Fill in start
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": "*", "Hostname": "*", "Response Code": "timeout"}, ignore_index=True)
                    #print (df)
                    #Fill in end
            except Exception as e:
                #print (e) # uncomment to view exceptions
                df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": "*", "Hostname": "*", "Response Code": e}, ignore_index=True)
                continue

            else:
                #Fill in start
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                #Fill in end
                try: #try to fetch the hostname of the router that returned the packet - don't confuse with the hostname that you are tracing
                    #Fill in start
                    addr = addr[0]
                    deviceHostname = gethostbyaddr(addr)[0]
                    #Fill in end
                except herror:   #if the router host does not provide a hostname use "hostname not returnable"
                    #Fill in start
                    deviceHostname = "Hostname not returnable"
                    #Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": destAddr, "Hostname": deviceHostname, "Response Code": "TTL Expired"}, ignore_index=True)
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": destAddr, "Hostname": deviceHostname, "Response Code": "End-Point Unreachable"}, ignore_index=True)
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should update your dataframe with the required column field responses here
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": addr, "Hostname": deviceHostname, "Response Code": "End-Point Reached"}, ignore_index=True)
                    #Fill in end
                    return df
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your df here
                    df = df.append({"Hop Count": ttl, "Try": tries+1, "IP": addr, "Hostname": deviceHostname, "Response Code": "Unknown Error"}, ignore_index=True)
                    #Fill in end
                break
    return df

if __name__ == '__main__':
    get_route("google.co.il")
