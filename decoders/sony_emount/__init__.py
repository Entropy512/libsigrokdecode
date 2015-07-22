##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2012 Uwe Hermann <uwe@hermann-uwe.de>
## Copyright (C) 2015 Andrew Dodd <atd7@cornell.edu>
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

'''
The Sony "E" lens mount is used by Sony's mirrorless cameras to attach lenses.

The mount is fully electronic with no mechanical focus/aperture drive, making
it easier to implement.  There are 10 pins in the mount:
LENS_GND - Ground for lens motor power
LENS_POWER - Lens motor power.  This can be either 5.0v or unregulated Vbat
(7.4v nominal li-ion), the body chooses based on an as-yet undetermined
negotiation with the lens
LOGIC_GND - Ground for lens logic circuitry
BODY_VD_LENS - Unknown but appears to be a wakeup interrupt.  Normally high,
brief pulses low at 60 Hz on a US body.  (TBD - Is this 50 on a PAL body?)
LOGIC_VCC - Lens logic power, 3.15v nominal
LENS_CS_BODY - Handshaking/ACK line from lens to body.  Normally low, always
high when the lens is sending data on TXD.  Also goes high without data
transmission during a speed negotiation.
RXD - UART data from lens to body.  Starts at 750 kbaud at power-on, typically
negotiates upwards to 1500 kbaud.  8N1, lsb-first
TXD - UART data from body to lens.  Same speeds as above
BODY_CS_LENS - Handshaking/ACK line from body to lens.  Same behavior as
LENS_CS_BODY but indicating activity on TXD

There is always only one packet sent per raising of a given direction's
handshaking line.  Once the packet is sent, the line goes low.

All packets start with an 0xF0 sync character.  With 8N1 lsb-firstserial, this leads
to five low bit times followed by five high bit times, allowing for UART speed to be
detected.

All packets end with either a 0x55 byte, or 0x55 followed by multiple 0x00 bytes.
So far I have never seen non-null data after a 0x55 end sync.

All logic signals are 3.15v high, 0v low.
'''

from .pd import Decoder
