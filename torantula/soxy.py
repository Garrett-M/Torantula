#!/usr/bin/env python3

from threading import Thread

import ipaddress
import socket
import socketserver
import sys
import time

""" Constants """
# Configuration
BUFFER_LEN = 8192
RESEND_TIMEOUT = 120
HOST = "127.0.0.1"
PORT = 9000

VERSION = b"\x05"
RESERVED = b"\x00"

# Authentication methods
AUTH_NONE = b"\x00"
AUTH_NOT_ACCEPTABLE = b"\xFF"

# Address types
ADDR_IPV4 = b"\x01"
ADDR_DOMAIN = b"\x03"
ADDR_IPV6 = b"\x04"

# Command types
CMD_CONNECT = b"\x01"
CMD_BIND = b"\x02"
CMD_UDP = b"\x03"

# Status
STAT_SUCCESS = b"\x00"
STAT_GENERAL_ERROR = b"\x01"
STAT_NOT_IN_RULESET = b"\x02"
STAT_NETWORK_UNREACHABLE = b"\x03"
STAT_HOST_UNREACHABLE = b"\x04"
STAT_CONNECTION_REFUSED = b"\x05"
STAT_TTL_EXPIRED = b"\x06"
STAT_COMMAND_UNSUPPORTED = b"\x07"
STAT_ADDRESS_TYPE_UNSUPPORTED = b"\x08"


class SocksException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class Forwarder(Thread):
    """
    Forwards all TCP traffic from src to destination.

    :param src: socket.socket connecting to the source
    :param dst: socket.socket connecting to the destination

    Does not close src or dst sockets
    """
    def __init__(self, src, dst):
        """
        Create a new Forwarder object

        :param src: socket.socket connecting to the source
        :param dst: socket.socket connecting to the destination
        """
        Thread.__init__(self)
        self.src = src
        self.dst = dst
        self.daemon = True

    def run(self):
        try:
            data = self.src.recv(BUFFER_LEN)

            while data:
                self.dst.sendall(data)
                data = self.src.recv(BUFFER_LEN)
        except socket.error:
            pass


class CommandHandler:
    """
    Abstract class for deciding how to handle CONNECT, BIND, and UDP ASSOCIATE commands once the SOCKS protocol stuff
    has been dealt with

    This is probably the class you want to override if you want to do some special handling

    :param command: the SOCKS command, either CONNECT, BIND, or UDP ASSOCIATE
    :param src_socket: socket.socket connecting to the source
    :param src_info: tuple containing the address as a string and the port as an integer
    :param dst_address: string of the address of the destination.
    :param dst_port: integer of the port of the destination

    Does not close the src socket
    """
    def __init__(self, command, src_socket, src_info, dst_address, dst_port):
        """
        Create a new SocksRequestHandler object

        :param command: the SOCKS command, either CONNECT, BIND, or UDP ASSOCIATE
        :param src_socket: socket.socket connecting to the source
        :param src_info: tuple containing the address as a string and the port as an integer
        :param dst_address: string of the address of the destination.
        :param dst_port: integer of the port of the destination
        """
        self.command = command
        self.src_socket = src_socket
        self.src_info = src_info
        self.dst_address = dst_address
        self.dst_port = dst_port

        self.src_ip_bytes = ipaddress.IPv4Address(src_info[0]).packed
        self.src_port_bytes = src_info[1].to_bytes(2, "big")

    def handle(self):
        """
        Calls the handle method corresponding to the SOCKS command
        """
        if self.command == CMD_CONNECT:
            return self.handle_connect()
        elif self.command == CMD_BIND:
            return self.handle_bind()
        elif self.command == CMD_UDP:
            return self.handle_udp()
        else:
            return self._send_unsupported()

    def handle_connect(self):
        pass

    def handle_bind(self):
        pass

    def handle_udp(self):
        pass

    def handle_unsupported(self):
        """ Handles when the given command is unsupported """
        self._send_unsupported()

    def _send_message(self, status, ip_address='', port=''):
        """ Convenience function for sending a status """
        if ip_address == '':
            ip_address = self.src_ip_bytes
        if port == '':
            port = self.src_port_bytes

        try:
            self.src_socket.sendall(VERSION + status + RESERVED + ADDR_IPV4 + ip_address + port)
        except BrokenPipeError:
            pass

    def _send_tcp_success(self):
        self._send_message(STAT_SUCCESS)

    def _send_unsupported(self):
        try:
            self.src_socket.sendall(VERSION + STAT_COMMAND_UNSUPPORTED + self.src_ip_bytes + self.src_port_bytes)
        except BrokenPipeError:
            pass


class SimpleCommandHandler(CommandHandler):
    """
    Simple implementation of a CommandHandler. Only supports CONNECT, which is to say TCP traffic

    Does not close the src socket
    """
    def handle_connect(self):
        """
        Handles a connect request.
        """
        dst_socket = None

        try:
            dst_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            dst_socket.connect((self.dst_address, self.dst_port))

            Logger.get().log('{}:{} <-> {}:{}'.format(self.src_info[0], self.src_info[1],
                                                      self.dst_address, self.dst_port))

            self._send_tcp_success()

            Forwarder(self.src_socket, dst_socket).start()
            Forwarder(dst_socket, self.src_socket).run()
        except socket.GeneralProxyError as e:
            self._send_message(STAT_GENERAL_ERROR)  # TODO more specific error code
            Logger.get().warn('{} on {}:{5:} -> {}:{}'
                              .format(e, self.src_info[0], self.src_info[1], self.dst_address, self.dst_port))
        finally:
            if dst_socket:
                dst_socket.close()

    def handle_bind(self):
        """ Should probably eventually implement """
        self.handle_unsupported()

    def handle_udp(self):
        """ Should probably eventually implement """
        self.handle_unsupported()


class SocksRequestHandler(socketserver.StreamRequestHandler):
    """
    A request handler that parses all the SOCKS protocol stuff and then sends the connection off to the connection
    handler
    """
    Handler = None

    @staticmethod
    def set_connection_handler(socks_handler):
        SocksRequestHandler.Handler = socks_handler

    def handle(self):
        try:
            self._read_client_greeting()

            if AUTH_NONE in self.methods:
                self.request.sendall(VERSION + AUTH_NONE)
            else:
                self.request.sendall(VERSION + AUTH_NOT_ACCEPTABLE)

            self._read_client_connection_request()

            handler = SocksRequestHandler.Handler(self.command, self.request, self.client_address,
                                                  self.dst_address, self.dst_port)
            handler.handle()
        except ConnectionResetError:
            pass
        except SocksException:
            handler = SocksRequestHandler.Handler(self.command, self.request, self.client_address,
                                                  self.dst_address, self.dst_port)
            handler.handle_unsupported()
        except Exception as e:
            raise e

    def _read_client_greeting(self):
        """
        Reads the SOCKS greeting and populates the self.greeting_version, self,num_methods, and self.methods
        """
        self.greeting_version = self.request.recv(1)
        self.num_methods = int.from_bytes(self.request.recv(1), "big")
        self.methods = self.request.recv(self.num_methods)

    def _read_client_connection_request(self):
        """
        Reads the client connection request, and populates:
            self.connection_version, self.command, self.reserved, self.address_type, self.dst_address, self.dst_port
        """
        self.connection_version = self.request.recv(1)
        self.command = self.request.recv(1)
        self.reserved = self.request.recv(1)
        self.address_type = self.request.recv(1)

        if self.address_type == ADDR_IPV4:
            dst_address_bytes = self.request.recv(4)
            dst_port_bytes = self.request.recv(2)

            self.dst_address = str(ipaddress.IPv4Address(dst_address_bytes))
        elif self.address_type == ADDR_DOMAIN:
            name_len = ord(self.request.recv(1))
            dst_address_bytes = self.request.recv(name_len)
            dst_port_bytes = self.request.recv(2)

            self.dst_address = dst_address_bytes.decode("utf-8")
        elif self.address_type == ADDR_IPV6:  # TODO: Test this
            dst_address_bytes = self.request.recv(16)
            dst_port_bytes = self.request.recv(2)

            self.dst_address = str(ipaddress.IPv6Address(dst_address_bytes))
        else:  # TODO: Possible bug here, inspect further
            Logger.get().warn("Invalid address type: {}".format(self.address_type))
            self.dst_address = "0.0.0.0"
            self.dst_port = 0
            raise SocksException("Invalid address type: {}".format(self.address_type))

        self.dst_port = int.from_bytes(dst_port_bytes, "big")


class Logger:
    """
    Logger class. It logs
    """
    _logger = None
    output = sys.stdout

    INFO = "[INFO]"
    WARN = "[WARN]"
    ERROR = "[ERROR]"

    def log(self, message):
        self.write(message, self.INFO)

    def warn(self, message):
        self.write(message, self.WARN)

    def error(self, message):
        self.write(message, self.ERROR)

    def write(self, message, level):
        self.output.write("{} {:7} {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), level, message))

    @staticmethod
    def get():
        if not Logger._logger:
            Logger._logger = Logger()

        return Logger._logger

    @staticmethod
    def set_output(output):
        Logger.output = output


class Server(socketserver.ThreadingTCPServer):
    """
    A Threading TCP Server that will parse SOCKS request parameters and lets the user work directly with the command
    handlers
    """
    def __init__(self, server_address, CommandHandlerClass):
        super(Server, self).__init__(server_address, SocksRequestHandler)

        SocksRequestHandler.set_connection_handler(CommandHandlerClass)

        self.allow_reuse_address = True
        self.timeout = RESEND_TIMEOUT


if __name__ == "__main__":
    server = Server((HOST, PORT), SimpleCommandHandler)

    Logger.get().log("Listening on {}:{}".format(HOST, PORT))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

