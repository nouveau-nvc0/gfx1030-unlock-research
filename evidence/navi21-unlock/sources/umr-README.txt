User Mode Register Debugger for AMDGPU Hardware
Copyright (c) 2025 AMD Inc.

Introduction
-------------

umr is a userspace debugging and diagnostic tool for AMD GPUs using
the AMDGPU kernel driver with limited support for driverless debugging
(via PCI direct access).

The tool allows reading/writing MMIO registers, analyzing wavefronts,
ring contents, as well as performance tracking.  It supports hardware
from SI based hardware onwards and requires a v4.10 kernel or newer
to function correctly.  Older kernels (not older than v4.8) may work
but with limited functionality/stability.  Older kernels are not supported
officially so please refrain from submitting bug reports in relation
to them.

The tool is open source and hosted at

    : https://gitlab.freedesktop.org/tomstdenis/umr

Users may report bugs, feedback, and submit patches to the amd-gfx
mailing list at:

    : https://lists.freedesktop.org/mailman/listinfo/amd-gfx

Online documentation is available at:

    : https://umr.readthedocs.io/en/main/

Building
---------

To build umr you will need pciaccess, ncurses, libdrm, llvm and
pthread headers and libraries. To enable the graphical frontend,
you'll also need sdl2.

To build umr:

    $ cmake -B build-dir -S .
    $ cmake --build build-dir

and then to install:

    $ cmake --install build-dir

To build rpm and deb packages, you will need rpmbuild, dpkg and cpack.
To build:

    $ cpack

and then to install:

    $ sudo rpm -i ./umr-1.0.1-Linux.rpm # or
    $ sudo dpkg -i ././umr-1.0.1-Linux.deb

If you plan to use it as a non-root user you may want to add the
setuid bit:

    $ chmod +s `which umr`

NOTE:  Allowing untrusted users access to umr may lead to system
comprimises, instability, and hardware damage.  Do not setuid this
tool on multi-user systems.

NOTE:  You may disable LLVM dependencies by adding UMR_NO_LLVM to your
environment.  e.g.,

    $ cmake -DUMR_NO_LLVM=ON ...

NOTE:  You may disable libDRM dependencies by adding UMR_NO_DRM to your
environment.  e.g.,

    $ cmake -DUMR_NO_DRM=ON ...

NOTE:  You may disable the graphical frontend by adding UMR_NO_GUI to your
environment.  e.g.,

    $ cmake -DUMR_NO_GUI=ON ...

NOTE:  You can disable the server feature by adding UMR_NO_SERVER to your
environment.  e.g.,

    $ cmake -DUMR_NO_SERVER=ON ...

NOTE:  You can build a static UMR executable by adding UMR_STATIC_EXECUTABLE
to your environment:

    $ cmake -DUMR_STATIC_EXECUTABLE=ON ...

This makes it easier to distribute UMR to test machines. However, static
executable builds have some limitations:

* GUI is not supported
* BO import is not supported
* Hostname lookup when specifying addresses on the command-line may not work
* NanoMsg only builds a shared library by default. If you want GUI server
  support, you may have to build and install your own static NanoMsg library
  from source and set the PKG_CONFIG_PATH environment variable appropriately.

You may also see linker warnings:

* A warning related to the getaddrinfo limitation.
* Warnings related to libLLVMSupport.a; those are harmless.

Running umr
------------

umr is a command line which parses options and commands from the
command line supplied.  It processes options first, then anything
that creates an ASIC model, then any commands to run.  So it is
agnostic to the order they appear on the command line.

For instance

    $ umr -r *.dce100.mmFOO -O bits

*is* the same as

    $ umr -O bits -r *.dce100.mmFOO

Users can get help with command options via

    $ umr -h

or
    $ man umr

Options can be stacked with commas.  For instance:

    $ umr -O bits,follow,empty_log -ls


Database files 
---------------

umr now uses a database of text files for registers, IP, ans ASIC
modelling information.  If umr is installed properly this shouldn't
be apparent to the user.  If you do however see an error message such as:

'[ERROR]: Cannot find asic file [%s] see README for more information'

That means umr cannot find the ASIC model database file (and likely any
other file under it).  In that case make sure there is a umr/database directory
installed in the share directory relative to where the binary is for example if the
binary is in /usr/local/bin/ then the database is expected to be in 
/usr/local/share/umr/.

If for whatever reason this isn't the case and cannot be installed then you can
use the UMR_DATABASE_PATH environment variable to point to the base of the
database tree.

If you want to override the umr provided database with your own content you can
use the command line option --database-path (-dbp) to specify a path (which will
be searched before UMR_DATABASE_PATH and before the default install directory).


Running umr GUI
-------------------

umr can be run in GUI mode using

    $ umr --gui

The other umr options still apply but must be used before --gui.

In GUI mode, umr can also connect to a remote umr instance. For instance,
on machine A run:

    $ umr --server tcp://0.0.0.0:1234

And on machine B run:

    $ umr --gui  tcp://machineA-IP:1234

This way the actions taken on umr on machine B will be forwarded to machine
A's umr instance.


Selecting Hardware
-------------------

On machines with more than one AMDGPU device umr can be instructed
which to look at.  If the driver is loaded and display attached [*]
the --instance option can select a device.  The devices can be listed
with the --enumerate option.

[*] Kernels v4.11 and newer only require the amdgpu module to be loaded
in order to work without '-f'.

Once one is picked the number can be used for instance:

    $ umr -i 1 -r *.*.CP_RB_BASE

Would read the CP ring buffer base address register(s).

If the AMDGPU driver is not loaded you can specify a device by name
or PCI device ID for instance:

    $ umr -f tahiti -r *.*.CP_RB_BASE

or

    $ umr -f 0x6780 -r *.*.CP_RB_BASE

Would read the CP ring base address from the first tahiti device in the system.
Note that the '-f' command does not support two instances of the same
hardware.  To choose between those the --instance command needs to be
used.


Quick Guide
------------

To read a specific register the --read command can be used:

    $ umr -r tahiti.uvd4.mmUVD_VCPU_CNTL

Would read the mmUVD_VCPU_CNTL register of the uvd4 block.  The asic
name can be replaced with * to simplify scripting, for instance:

    $ umr -r *.uvd4.mmUVD_VCPU_CNTL

Registers can be written with --write and --writebit commands.

To read ring contents the --ring command can be used.  Optionally,
ranges can be specified or by default it will read from 32 words before
the read pointer upto the write pointer.

The kernel supports a MMIO tracepoint and can be read with the
--logscan command.  Normally, one would want to follow it so the
typical use would be

    $ umr -O bits,follow,empty_log -ls

GPU Utilization
----------------

The GPU utilization can be summarize with the --top command.  It is
an interactive mode of umr which samples various registers and
prints out the counts.

When this mode is active the frequency of sampling can be changed by
hitting '1'.  It defaults to 100Hz but can be increased to 1000Hz.  The
frequency of reporting can be changed with '2' from 1Hz to 10Hz.

Various fields can be enabled with keys indicated at the bottom of the
screen.  When all the desired options are enabled the 'W' (upper case)
can be hit to write the configuration to disk.

The fields can be logged to disk by hitting 'l' to toggle the logging
on and off.  By default, it will write to ~/umr.log in comma separated
value format.  It appends to the file so it can be toggled on and off
as a test is instrumented.  The first column includes an uptime counter
so it can be used to sort the output.

The use_colour (also: use_color) option can be specified to colourize
the display making seeing busy bits easier to see.

Wavefront Debugging
--------------------

The status of valid wavefronts can be displayed with the --waves
command.  The bits option enables bitfield decoding.  Normally,
the columns would be pretty printed:

    $ umr -wa

Note that wave fetching is unstable if GFX PG is enabled as reading
some of the wave related registers can lead to GPU hangs while the GFX
block is transitioning.
