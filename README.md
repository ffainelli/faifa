# faifa
Faifa can configure any Intellon-based Power Line Communication device using Intellon INT5000 and INT6000 
series chips (6000 and 6300 chips). 

It supports all Intellon-specific management and control frames as well as standard management frames. 

This fork has been made in order to better decode HP-AV frames in sniffer mode according to the IEEE 1901-2010 standard.

Specifically, the modules homeplug_av.h and frame.c have had structures and functions added for decoding frames 
differentially according to delimiter type, and also for decoding beacon MPDU payload. 

Various changes made to better describe fields and give values in both decimal and hex (and occasionally binary).

Tested using Debian GNU/Linux 8 with a variety of Homeplug adapters having both QCA and Broadcmm chipsets.

(Obviously, the Broadcom chipsets don't implement the Intellon/QCA proprietary sniffer mode, but the frames they 
emit can be successfully sniffed once an Intellon/QCA adapter is added to a Broadcmm Homeplug network).
