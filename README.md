# FuseSMB-Haiku

This is the Haiku port of fusesmb.

fusesmb Copyright (C) 2003-2006 Vincent Wagelaar <vincent@ricardis.tudelft.nl>

Haiku port and extensions Copyright (C) 2017 Julian Harnath <julian.harnath@rwth-aachen.de>

FuseSMB provides access to shared files and folders using the
Server Message Block (SMB) protocol. One version of the protocol is also
known as Common Internet File System (CIFS).

FuseSMB features automatic discovery of servers and shares and displays
them as a folder hierarchy in a virtual volume right on your desktop.
It also includes a network preferences add-on, where you can enable and
configure it.

### Building

Requirement is Haiku hrev >= 50983 with the userland_fs and samba_devel packages
installed.
Easiest is to build it into an HPKG using haikuporter, there's a build
recipe called fusesmb_haiku in the haikuports repository.
To build by hand, simply run jam. If you're building for Haiku gcc2h,
you also need to supply the paramter "-sGCC2H=1" to jam.

### License

There are several free software licenses used by different parts of
FuseSMB-Haiku. Please see the license header at the top of each source
file to find out under which license it is.

The file "license/GPLv2" contains the text for GPLv2, as found in
the original fusesmb release as "COPYING". The MIT license used by the
files which were added by me is included in the file "license/MIT".
Other licenses are also found at the top of source files
(e.g. in fusesmb/hash.c).

### Original ReadMe

The original fusesmb readme can be found in fusesmb/README.

### Additional credits

Thanks to Vincent Wagelaar for writing the original fusesmb.

Thanks to humdinger for creating nice icons.
