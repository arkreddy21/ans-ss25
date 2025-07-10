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
from lib.worker import *
from lib.comm import send, receive
from scapy.all import Packet, ByteField, IntField, FieldListField
import socket

NUM_ITER   = 3
CHUNK_SIZE = 64

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        FieldListField("chunk", None, IntField("num",0))
    ]

def AllReduce(soc, rank, data, result):
    """
    Perform in-network all-reduce over UDP

    :param str    soc: the socket used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector

    This function is blocking, i.e. only returns with a result or error
    """

    # NOTE: Do not send/recv directly to/from the socket.
    #       Instead, please use the functions send() and receive() from lib/comm.py
    #       We will use modified versions of these functions to test your program
    for i in range(0, len(data), CHUNK_SIZE):
        # Send packet and wait for response
        payload = bytes(SwitchML(rank=rank, chunk=data[i:i+CHUNK_SIZE]))
        send(soc, payload, ("10.0.1.1", 50505))
        res_packet, _ = receive(soc, 1024)
        result[i:i+CHUNK_SIZE] = SwitchML(res_packet).chunk
        Log(SwitchML(res_packet).chunk)

def main():
    rank = GetRankOrExit()

    # Create a UDP socket. 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #NOTE: using empty ip to receive broadcast packets
    s.bind(("", 50505))

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("udp-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()