#!/usr/bin/env python3
# License: CC0 1.0 Universal
# Author: opatuo
import binaryninja
import argparse
import ipaddress
import socket
from binjalib import varslice
from binjalib import search
from pathlib import Path


def socket_type_to_string(sock_type: int):
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP"
    if sock_type == socket.SOCK_RAW:
        return "RAW"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Find Open Ports", description="Search a binary for open ports"
    )
    parser.add_argument("filename")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if not args.verbose:
        binaryninja.disable_default_log()

    with binaryninja.load(args.filename) as bv:
        print(f"{Path(args.filename).stem}:")
        for reference in search.calls_to(bv, "bind"):
            callers = bv.get_functions_containing(reference.address)
            for caller in callers:
                socket_fd, sockaddr, sockaddr_size = search.variables_at(
                    caller, reference
                )

                caller, original_sockaddr = varslice.backward(caller, sockaddr.src)

                sockaddr_len = int(str(sockaddr_size), 16)
                if sockaddr_len == 16:
                    socket_type_value = search.function_parameter_initialization_of(
                        socket_fd.src, caller, 1
                    )
                    socket_type = socket_type_to_string(socket_type_value)

                    original_sockaddr.type, _ = bv.parse_type_string("sockaddr_in")

                    in_port_t = search.initialization_of_type(bv, caller, ["in_port_t"])
                    port_value = search.function_parameter_initialization_of(
                        in_port_t, caller, 0
                    )
                    print(f"\t{socket_type} PORT == {port_value}")

                    sin_addr = search.initialization_of_type_at(
                        bv, caller, "sockaddr_in", 4
                    )
                    address_value = search.function_parameter_initialization_of(
                        sin_addr.src, caller, 0
                    )
                    print(f"\tADDRESS  == {str(ipaddress.IPv4Address(address_value))}")
                else:
                    raise Exception(f"Unknown sockaddr length: {sockaddr_len}")
