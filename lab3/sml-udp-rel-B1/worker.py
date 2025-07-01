"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import GetRankOrExit, Log
from lib.comm import send, receive, unreliable_send, unreliable_receive
from scapy.all import Packet, ByteField, IntField, FieldListField
import socket

NUM_ITER   = 3
CHUNK_SIZE = 64
TIMEOUT = 1

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        ByteField("chunkId", 0),
        FieldListField("data", None, IntField("elem",0))
    ]

def AllReduce(soc, rank, data, result):
    """
    Perform reliable in-network all-reduce over UDP

    :param str    soc: the socket used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """

    # TODO: Implement me
    # NOTE: Do not send/recv directly to/from the socket.
    #       Instead, please use the functions send() and receive() from lib/comm.py
    #       We will use modified versions of these functions to test your program
    #
    #       You may use the functions unreliable_send() and unreliable_receive()
    #       to test how your solution handles dropped/delayed packets
    
    for i in range(0, len(data), CHUNK_SIZE):
        chunkId = int(i / CHUNK_SIZE)
        payload = bytes(SwitchML(rank=rank, chunkId=chunkId, data=data[i:i+CHUNK_SIZE]))

        while True:
            unreliable_send(soc, payload, ("10.0.1.1", 50505), p=0.1)
            # Try to receive packet. Send again if failed
            try:
                rec_packet, _ = unreliable_receive(soc, 1024, p=0.1)
            except socket.timeout:
                Log(f"Worker {rank}: Socket Timeout")
                continue
            
            rec_packet = SwitchML(rec_packet)
            if rec_packet.rank != 0xFF or rec_packet.chunkId != chunkId:
                Log(f"Worker {rank}: wrong packet")
                continue
            result[i:i+CHUNK_SIZE] = rec_packet.data
            Log(rec_packet.data)
            break

    # Send acknowledgement to signify the end of an iteration
    # chunkId=0xff to signify there is no chunk data. This is just an acknowledgement
    final_ack = bytes(SwitchML(rank=rank, chunkId=0xff, data=[0 for j in range(CHUNK_SIZE)]))
    while True:
        unreliable_send(soc, final_ack, ("10.0.1.1", 50505), p=0.1)
        try:
            rec_packet, _ = unreliable_receive(soc, 1024, p=0.1)
        except socket.timeout:
            continue
        rec_packet = SwitchML(rec_packet)
        if rec_packet.rank != 0xFF or rec_packet.chunkId != 0xFF:
            continue
        Log(f"Worker {rank}: Final Ack Done")
        break
    

def main():
    rank = GetRankOrExit()

    # Create a UDP socket. 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 50505))
    s.settimeout(TIMEOUT)

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("udp-rel-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-rel-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()