# MSNCSIASM

## Introduction

Small project to teach myself the basics of x86 assembly that is also something
I can actually make use of afterwards.

The program will query Microsoft's NCSI (Network Connectivity Status Indicator)
service and exit with a status code relevant to your own Internet connectivity
status.  An exit status of zero means you have a working connection to the
Internet. Any other exit status means you have partial or no Internet
connectivity.

## Operation

The operation is based on the answer found here: [How does Windows know whether
it has internet access or if a Wi-Fi connection requires in-browser
authentication?](http://superuser.com/questions/277923/how-does-windows-know-whether-it-has-internet-access-or-if-a-wi-fi-connection-re)

The program will perform two tests:

1. GET request for http://www.msftncsi.com/ncsi.txt
2. DNS request for dns.msftncsi.com

If the GET request succeeded and the content was correct, it stops there and
will exit with 0.

If the GET request succeeded, but the content was not correct, it will perform
the second test.

If the second test succeeds, it will stop there and exit with 1 (to
differenciate).

Otherwise, it will exit with a non-zero exit status.

## Installation

To assemble the program, run the make command in the directory appropriate for
the OS and architecture.

    cd <OS>/<arch>
    make

## Usage

The command has no input and provides no output except its exit status.

    ./msncsi
    echo $?

It could be used in bash scripts, for example:

    if ./msncsi; then
        echo "I'm online :-)"
    else
        echo "I'm offline :-("
    fi

## byteswap

Two additional programs were created to transform numbers into network byte
order for use in the main program's source code. Assuming you are on a
little-endian system. The first, byteswap, takes a 16bit number on the
command-line and returns the number in hex after the swap. This is useful for
port numbers. The second, byteswapip, takes an IP address and performs a
similar operation.

These programs were also created partially for learning. Their functionality
can be found in calculator software bundled with modern operating systems, so
are not strictly necessary.
