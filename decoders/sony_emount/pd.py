##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2011-2014 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
##

import sigrokdecode as srd
from math import floor, ceil
from binascii import hexlify
import struct

'''
OUTPUT_PYTHON format:

Packet:
[<ptype>, <rxtx>, <pdata>]

This is the list of <ptype>s and their respective <pdata> values:
 - 'STARTBIT': The data is the (integer) value of the start bit (0/1).
 - 'DATA': This is always a tuple containing two items:
   - 1st item: the (integer) value of the UART data. Valid values
     range from 0 to 512 (as the data can be up to 9 bits in size).
   - 2nd item: the list of individual data bits and their ss/es numbers.
 - 'PARITYBIT': The data is the (integer) value of the parity bit (0/1).
 - 'STOPBIT': The data is the (integer) value of the stop bit (0 or 1).
 - 'INVALID STARTBIT': The data is the (integer) value of the start bit (0/1).
 - 'INVALID STOPBIT': The data is the (integer) value of the stop bit (0/1).
 - 'PARITY ERROR': The data is a tuple with two entries. The first one is
   the expected parity value, the second is the actual parity value.
 - TODO: Frame error?

The <rxtx> field is 0 for RX packets, 1 for TX packets.
'''

# Used for differentiating between the two data directions.
RX = 0
TX = 1

class SamplerateError(Exception):
    pass

class ChannelError(Exception):
    pass

class Decoder(srd.Decoder):
    api_version = 3
    id = 'sony_emount'
    name = 'E-Mount'
    longname = 'Sony E-Mount lens protocol'
    desc = 'Lens control for interchangeable lens camera.'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['sony_emount']
    tags = ['Embedded/industrial']
    channels = (
        # Allow specifying only one of the signals, e.g. if only one data
        # direction exists (or is relevant).
        {'id': 'rx', 'name': 'RXD', 'desc': 'Lens data receive line'},
        {'id': 'tx', 'name': 'TXD', 'desc': 'Lens data transmit line'},
        {'id': 'rx_cs', 'name': 'LENS_CS_BODY', 'desc': 'Lens data RX handshake'},
        {'id': 'tx_cs', 'name': 'BODY_CS_LENS', 'desc': 'Lens data TX handshake'},
    )
    options = (
        {'id': 'format', 'desc': 'Data format', 'default': 'hex',
            'values': ('ascii', 'dec', 'hex', 'oct', 'bin')},
        {'id': 'invert_rx', 'desc': 'Invert RX?', 'default': 'no',
            'values': ('yes', 'no')},
        {'id': 'invert_tx', 'desc': 'Invert TX?', 'default': 'no',
            'values': ('yes', 'no')},
    )
    annotations = (
        ('rx-data', 'RX data'),
        ('tx-data', 'TX data'),
        ('rx-start', 'RX start bits'),
        ('tx-start', 'TX start bits'),
        ('rx-parity-ok', 'RX parity OK bits'),
        ('tx-parity-ok', 'TX parity OK bits'),
        ('rx-parity-err', 'RX parity error bits'),
        ('tx-parity-err', 'TX parity error bits'),
        ('rx-stop', 'RX stop bits'),
        ('tx-stop', 'TX stop bits'),
        ('rx-warnings', 'RX warnings'),
        ('tx-warnings', 'TX warnings'),
        ('rx-data-bits', 'RX data bits'),
        ('tx-data-bits', 'TX data bits'),
        ('rx-sync-byte', 'RX Sync byte calculated baudrate'),
        ('tx-sync-byte', 'TX Sync byte calculated baudrate'),
        ('rx-packets', 'RX packets'),
        ('tx-packets', 'TX packets'),
        ('rx-focus', 'Focus Data'),
    )
    annotation_rows = (
        ('rx-packets', 'RX packets', (16,)),
        ('rx-data', 'RX', (0, 2, 4, 6, 8, 14)),
        ('rx-data-bits', 'RX bits', (12,)),
        ('rx-warnings', 'RX warnings', (10,)),
        ('tx-packets', 'TX packets', (17,)),
        ('tx-data', 'TX', (1, 3, 5, 7, 9, 15)),
        ('tx-data-bits', 'TX bits', (13,)),
        ('tx-warnings', 'TX warnings', (11,)),
        ('rx-focus', 'Focus Data', (18,)),
    )
    binary = (
        ('rx', 'RX dump'),
        ('tx', 'TX dump'),
        ('rxtx', 'RX/TX dump'),
    )

    def escapebyte(self,b):
        return '{:02X} '.format(b)

    def putsync(self, rxtx, data):
        s = self.sync_start[rxtx]
        self.put(s, int(s + 10 * self.bit_width), self.out_ann, data)

    def putpacket(self, rxtx, data):
        s,n = self.packet_start[rxtx],self.samplenum
        self.put(s, n, self.out_ann, data)

    def putfocus(self, rxtx, data):
        s,n = self.packet_start[rxtx],self.samplenum
        self.put(s,n, self.out_ann, data)

    def putx(self, rxtx, data):
        s, halfbit = self.startsample[rxtx], self.bit_width / 2.0
        self.put(s - floor(halfbit), self.samplenum + ceil(halfbit), self.out_ann, data)

    def putpx(self, rxtx, data):
        s, halfbit = self.startsample[rxtx], self.bit_width / 2.0
        self.put(s - floor(halfbit), self.samplenum + ceil(halfbit), self.out_python, data)

    def putg(self, data):
        s, halfbit = self.samplenum, self.bit_width / 2.0
        self.put(s - floor(halfbit), s + ceil(halfbit), self.out_ann, data)

    def putp(self, data):
        s, halfbit = self.samplenum, self.bit_width / 2.0
        self.put(s - floor(halfbit), s + ceil(halfbit), self.out_python, data)

    def putbin(self, rxtx, data):
        s, halfbit = self.startsample[rxtx], self.bit_width / 2.0
        self.put(s - floor(halfbit), self.samplenum + ceil(halfbit), self.out_bin, data)

    def __init__(self):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.samplenum = 0
        self.frame_start = [-1, -1]
        self.sync_start = [-1, -1]
        self.startbit = [-1, -1]
        self.cur_data_bit = [0, 0]
        self.databyte = [0, 0]
        self.paritybit = [-1, -1]
        self.stopbit1 = [-1, -1]
        self.startsample = [-1, -1]
        self.state = ['WAIT FOR CS', 'WAIT FOR CS']
#        self.oldbit = [1, 1]
#        self.oldcs = [0, 0]
#        self.oldpins = [1, 1]
        self.databits = [[], []]
        #The below were optional in the uart module, but are fixed for e-mount
        self.baudrate = 750000.0 #This will be adjusted by sync byte detection eventually
        self.num_data_bits = 8
        self.bit_order = 'lsb-first'

        #New e-mount stuff...  Probably want to move this into an upper-level decoder
        self.packetdata = [[],[]]
        self.packet_start = [-1,-1]
        self.packet_end = [-1,-1]

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_bin = self.register(srd.OUTPUT_BINARY)
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value
            # The width of one UART bit in number of samples.
            self.bit_width = float(self.samplerate) / self.baudrate

    def get_sample_point(self, rxtx, bitnum):
        """Determine absolute sample number of a bit slot's sample point."""
        # bitpos is the samplenumber which is in the middle of the
        # specified UART bit (0 = start bit, 1..x = data, x+1 = parity bit
        # (if used) or the first stop bit, and so on).
        # The samples within bit are 0, 1, ..., (bit_width - 1), therefore
        # index of the middle sample within bit window is (bit_width - 1) / 2.
        bitpos = self.frame_start[rxtx] + (self.bit_width - 1) / 2.0
        bitpos += bitnum * self.bit_width
        return bitpos

    # Return true if we reached the middle of the desired bit, false otherwise.
    def reached_bit(self, rxtx, bitnum):
        bitpos = self.get_sample_point(rxtx, bitnum)
        if self.samplenum >= bitpos:
            return True
        return False

    def wait_for_cs(self, rxtx, signal):
        #CS is normally low and active high, wait for it to rise
        if signal != 1:
            return

        # TODO: Save where CS went high - The line below is from wait_for_start_bit, needs to be reworked
        #self.frame_start[rxtx] = self.samplenum

        #print("CS line went high on line " + str(rxtx) + " at time " + str(float(self.samplenum)/float(self.samplerate)))

        self.state[rxtx] = 'WAIT FOR SYNC BYTE'

    def wait_for_sync(self, rxtx, data):
        #Sync byte is always a low start bit followed by five more low bits
        if data != 0:
            return

        #Save the sample number where the sync byte begins
        self.sync_start[rxtx] = self.samplenum
        #print("Data line went low for sync at " + str(self.samplenum) + " on line " + str(rxtx))

        self.state[rxtx] = 'GET SYNC RATE'

    def get_sync_rate(self, rxtx, signal):
        if signal != 1:
            return

        elapsed_samples = self.samplenum - self.sync_start[rxtx]
        #print("Sync byte detected, elapsed_samples is " + str(elapsed_samples))
        elapsed_time = float(elapsed_samples) / float(self.samplerate)
        #print("Sync low time was " + str(elapsed_time))
        bit_time = elapsed_time / 5.0 #Sync byte is 1 start bit plus 4 low data bits
        self.baudrate = 1.0 / bit_time
        if(self.baudrate < 1e6):
            self.baudrate = 750000.0
        else:
            self.baudrate = 1500000.0
        self.bit_width = float(self.samplerate) / self.baudrate

        #print("Sync byte detected at " + str(self.samplenum) + " on line " + str(rxtx) + ", detected baudrate was " + str(self.baudrate))

        self.state[rxtx] = 'WAIT FOR START BIT'

        #self.putsync(rxtx, [rxtx + 14, ['Sync Byte %d' % self.baudrate, 'Sync %d' % self.baudrate, 'S:%d' % self.baudrate]])

    def wait_for_start_bit(self, rxtx, signal):
        # The caller already has detected an edge. Strictly speaking this
        # check on the current signal level is redundant. But it does not
        # harm either.
        if signal != 0:
            return

        # Save the sample number where the start bit begins.
        self.frame_start[rxtx] = self.samplenum

        self.state[rxtx] = 'GET START BIT'

    def get_start_bit(self, rxtx, signal):
        # Skip samples until we're in the middle of the start bit.
        if not self.reached_bit(rxtx, 0):
            return

        self.startbit[rxtx] = signal

        # The startbit must be 0. If not, we report an error.
        if self.startbit[rxtx] != 0:
            self.putp(['INVALID STARTBIT', rxtx, self.startbit[rxtx]])
            # TODO: Abort? Ignore rest of the frame?

        self.cur_data_bit[rxtx] = 0
        self.databyte[rxtx] = 0
        self.startsample[rxtx] = -1

        self.state[rxtx] = 'GET DATA BITS'

        self.putp(['STARTBIT', rxtx, self.startbit[rxtx]])
#        self.putg([rxtx + 2, ['Start bit', 'Start', 'S']])

    def get_data_bits(self, rxtx, signal):
        # Skip samples until we're in the middle of the desired data bit.
        if not self.reached_bit(rxtx, self.cur_data_bit[rxtx] + 1):
            return

        # Save the sample number of the middle of the first data bit.
        if self.startsample[rxtx] == -1:
            self.startsample[rxtx] = self.samplenum

        # Get the next data bit in LSB-first fashion. (E-mount does not have msb-first, but keep the code for now in case I'm wrong)
        if self.bit_order == 'lsb-first':
            self.databyte[rxtx] >>= 1
            self.databyte[rxtx] |= \
                (signal << (self.num_data_bits - 1))
        else:
            self.databyte[rxtx] <<= 1
            self.databyte[rxtx] |= (signal << 0)

        #self.putg([rxtx + 12, ['%d' % signal]])

        # Store individual data bits and their start/end samplenumbers.
        s, halfbit = self.samplenum, int(self.bit_width / 2)
        self.databits[rxtx].append([signal, s - halfbit, s + halfbit])

        # Return here, unless we already received all data bits.
        if self.cur_data_bit[rxtx] < self.num_data_bits - 1:
            self.cur_data_bit[rxtx] += 1
            return

        self.state[rxtx] = 'GET PARITY BIT' #FIXME - Remove all parity handling cruft for e-mount

        self.putpx(rxtx, ['DATA', rxtx,
            (self.databyte[rxtx], self.databits[rxtx])])

        if(len(self.packetdata[rxtx]) == 0):
            self.packetdata[rxtx].append(self.databyte[rxtx])
            self.packet_start[rxtx] = self.frame_start[rxtx]
        else:
            self.packetdata[rxtx].append(self.databyte[rxtx])
            self.packet_end[rxtx] = self.samplenum

        b, f = self.databyte[rxtx], self.options['format']
        if f == 'ascii':
            c = chr(b) if b in range(30, 126 + 1) else '[%02X]' % b
            self.putx(rxtx, [rxtx, [c]])
        elif f == 'dec':
            self.putx(rxtx, [rxtx, [str(b)]])
#        elif f == 'hex':
#            self.putx(rxtx, [rxtx, [hex(b)[2:].zfill(2).upper()]])
        elif f == 'oct':
            self.putx(rxtx, [rxtx, [oct(b)[2:].zfill(3)]])
        elif f == 'bin':
            self.putx(rxtx, [rxtx, [bin(b)[2:].zfill(8)]])

        self.putbin(rxtx, (rxtx, bytes([b])))
        self.putbin(rxtx, (2, bytes([b])))

        self.databits = [[], []]

    def get_parity_bit(self, rxtx, signal):
        #Clean this up to remove this function eventually, Sony E-mount always has no parity
        self.state[rxtx] = 'GET STOP BITS'
        return

    # TODO: Currently only supports 1 stop bit.
    def get_stop_bits(self, rxtx, signal):
        # Skip samples until we're in the middle of the stop bit(s).
        # E mount never uses parity, so we removed all of the skip_parity stuff
        b = self.num_data_bits + 1
        if not self.reached_bit(rxtx, b):
            return

        self.stopbit1[rxtx] = signal

        # Stop bits must be 1. If not, we report an error.
        if self.stopbit1[rxtx] != 1:
            self.putp(['INVALID STOPBIT', rxtx, self.stopbit1[rxtx]])
#            self.putg([rxtx + 8, ['Frame error', 'Frame err', 'FE']])
            # TODO: Abort? Ignore the frame? Other?

        self.state[rxtx] = 'WAIT FOR START BIT'

        self.putp(['STOPBIT', rxtx, self.stopbit1[rxtx]])
#        self.putg([rxtx + 4, ['Stop bit', 'Stop', 'T']])

    def get_wait_cond(self, rxtx, inv):
        """
        Determine Decoder.wait() condition for specified UART line.
        Returns condititions that are suitable for Decoder.wait(). Those
        conditions either match the falling edge of the START bit, or
        the sample point of the next bit time.
        """

        state = self.state[rxtx]
        if state == 'WAIT FOR CS':
            return {rxtx + 2: 'f' if inv else 'r'}
        elif state == 'WAIT FOR SYNC BYTE':
            return {rxtx: 'r' if inv else 'f'}
        elif state == 'GET SYNC RATE':
            return {rxtx: 'f' if inv else 'r'}
        if state == 'WAIT FOR START BIT':
            return {rxtx: 'r' if inv else 'f'}
        if state == 'GET START BIT':
            bitnum = 0
        elif state == 'GET DATA BITS':
            bitnum = 1 + self.cur_data_bit[rxtx]
        elif state == 'GET PARITY BIT':
            bitnum = 1 + self.num_data_bits
        elif state == 'GET STOP BITS':
            bitnum = 1 + self.num_data_bits
            #emount never has parity
            #bitnum += 0 if self.options['parity_type'] == 'none' else 1
        want_num = self.get_sample_point(rxtx, bitnum)
        # want_num = int(want_num + 0.5)
        want_num = ceil(want_num)
        cond = {'skip': want_num - self.samplenum}
        return cond

    def decode(self):
        if not self.samplerate:
            raise SamplerateError('Cannot decode without samplerate.')

        opt = self.options
        inv = [opt['invert_rx'] == 'yes', opt['invert_tx'] == 'yes']
        cond_idx = [None] * 3
        cond_idx[0] = 0
        
        while True:
            conds = []
            for rxtx in (RX, TX):
                conds.append(self.get_wait_cond(rxtx, inv[rxtx]))
                if not (self.state[rxtx] == 'WAIT_FOR_CS'):
                    conds.append({rxtx + 2: 'r' if inv[rxtx] else 'f'})
                cond_idx[rxtx + 1] = len(conds)

            (rx, tx, rx_cs, tx_cs) = self.wait(conds)

            if inv[RX]:
                rx = not rx
                rx_cs = not rx_cs
            if inv[TX]:
                tx = not tx
                tx_cs = not tx_cs

            # State machine.
            for rxtx in (RX, TX):
                found_match = False
                for j in range(cond_idx[rxtx],cond_idx[rxtx+1]):
                    #print(str(rxtx) + " " + str(j) + " " + str(self.matched[j]))
                    if self.matched[j]:
                        found_match = True
                if not found_match:
                    continue

                #print(str(rxtx) + " " + str(self.samplenum/self.samplerate) + " " + self.state[rxtx] + " " + str(conds))
                data_signal = rx if (rxtx == RX) else tx
                cs_signal = rx_cs if (rxtx == RX) else tx_cs

                if self.state[rxtx] == 'WAIT FOR CS':
                    self.wait_for_cs(rxtx, cs_signal)
                elif self.state[rxtx] == 'WAIT FOR SYNC BYTE':
                    self.wait_for_sync(rxtx, data_signal)
                elif self.state[rxtx] == 'GET SYNC RATE':
                    self.get_sync_rate(rxtx, data_signal)
                elif self.state[rxtx] == 'WAIT FOR START BIT':
                    self.wait_for_start_bit(rxtx, data_signal)
                elif self.state[rxtx] == 'GET START BIT':
                    self.get_start_bit(rxtx, data_signal)
                elif self.state[rxtx] == 'GET DATA BITS':
                    self.get_data_bits(rxtx, data_signal)
                elif self.state[rxtx] == 'GET PARITY BIT': #FIXME: Remove all parity handling stuff for emount
                    self.get_parity_bit(rxtx, data_signal)
                elif self.state[rxtx] == 'GET STOP BITS':
                    self.get_stop_bits(rxtx, data_signal)

                if(cs_signal == 0):
                    #print("CS went low on line " + str(rxtx) + " at time " + str(float(self.samplenum)/float(self.samplerate)))
                    if(self.state[rxtx] == 'WAIT FOR START BIT'):
                        packetbytes = bytes(self.packetdata[rxtx])
                        (packetlen,pkt_type,seqnum) = struct.unpack_from("<HBB",packetbytes)
                        packetlen -= 1
                        (checksum,stopbyte) = struct.unpack_from("<HB",packetbytes,packetlen-3)
                        packetdata_hex = ''.join([self.escapebyte(b) for b in self.packetdata[rxtx][4:packetlen-3]])
                        self.putpacket(rxtx, [rxtx + 16, ['{:0.6f}, Plen: {:04X}, ftype: {:02X}, snum: {:02X}, speed: {}, rxtx: {}, extra: {}, csum: {:04X}, data: "{}"'.format(self.packet_start[rxtx]/self.samplerate,packetlen+1,pkt_type,seqnum,self.baudrate,rxtx,len(self.packetdata[rxtx])-packetlen,checksum,packetdata_hex)]])
#                        if(self.packetid[rxtx] == 0x30):
#                            self.putfocus(rxtx, [18, ['{:0.6f}, {}, {}, , , , '.format(self.packet_start[rxtx]/self.samplerate,
#                                                                                self.packetdata[rxtx][7]*256+self.packetdata[rxtx][6],
#                                                                                self.packetdata[rxtx][25]*256+self.packetdata[rxtx][24]
#                                                                          )]])
#                        if(self.packetid[rxtx] == 0x32):
#                            self.putfocus(rxtx, [18, ['{:0.6f}, , , {}, {}, , '.format(self.packet_start[rxtx]/self.samplerate,
#                                                                                self.packetdata[rxtx][9]*256+self.packetdata[rxtx][8],
#                                                                                self.packetdata[rxtx][27]*256+self.packetdata[rxtx][26]
#                                                                          )]])
#                        if(self.packetid[rxtx] == 0x34):
#                            self.putfocus(rxtx, [18, ['{:0.6f}, , , , , {}, '.format(self.packet_start[rxtx]/self.samplerate,
#                                                                              self.packetdata[rxtx][11]*256+self.packetdata[rxtx][10]
#                                                                          )]])
#                        if(self.packetid[rxtx] == 0x27):
#                            self.putfocus(rxtx, [18, ['{:0.6f}, , , , , , {}'.format(self.packet_start[rxtx]/self.samplerate,
#                                                                              self.packetdata[rxtx][26]*256+self.packetdata[rxtx][25]
#                                                                          )]])
                    self.packetdata[rxtx] = []
                    self.state[rxtx] = 'WAIT FOR CS'

                # Save current RX/TX values for the next round.
#                self.oldbit[rxtx] = data_signal
#                self.oldcs[rxtx] = cs_signal
