#!/usr/bin/env python3

from os.path import expanduser
from threading import Thread
from stem.control import Controller

import argparse
import binascii
import ipaddress
import os
import signal
import socket
import socks
import soxy
import subprocess
import stem
import sys
import time
import traceback

####################
# ARGUMENT PARSING #
####################

__parser = argparse.ArgumentParser("Intermediate proxy to Tor")

# Major behavior
__parser.add_argument('port', type=int, nargs='?', default=9000, help='Port to run on')
__parser.add_argument('--launch', action='store_const', dest='mode', const='launch', default='attach',
                      help='Launch new tor instances rather than attach to existing ones')

# Tor connection 
__parser.add_argument('-p', type=int, dest='tor_port', default=9050, help='Port Tor is running on')
__parser.add_argument('-cp', type=int, dest='tor_control_port', default=9051,
                      help='Port that Tor uses as Control port')
__parser.add_argument('-cpp', type=str, dest='tor_control_password', default='', help='Tor control port password')

# Tor configuration
__parser.add_argument('--path', dest='tor_path', type=str, default='tor', help='Path to the Tor binary')
__parser.add_argument('-d', dest='tor_data_dir', type=str, default='~/.torantula/data/tor',
                      help='Tor data directory')

# Circuits configuration
__parser.add_argument('-c', type=int, dest='circuits', default=0, help='Number of circuits per process. If 0, '
                                                                       ' give each host own circuit')
__parser.add_argument('-n', type=int, dest='processes', default=1, help='Number of tor processes to run')

# Filtering
__parser.add_argument('--cidr', type=int, dest='cidr_mask', default=16,
                      help='The cidr mask used to determine if connections to ip addresses use the same '
                           'circuit (Default 16). Ex: 127.0.0.1/16 and 127.0.123.241/16 would both use the same circuit')

# Logging
__parser.add_argument('-v', dest='verbose', action='store_true', default=False, help='Enable verbose logging')
__parser.add_argument('-w', dest='show_warnings', action='store_true', default=False,
                      help='Enable proxy warning messages')

args = __parser.parse_args()

#####################
# /ARGUMENT PARSING #
#####################

logger = soxy.Logger.get()

_fatal_error_received = False
_dirname = os.path.dirname(os.path.realpath(__file__))

# Constants
PASSWORD_LENGTH = 32


def _log_verbose(message):
    if args.verbose:
        logger.log(message)


def _warn_verbose(message):
    if args.show_warnings:
        logger.warn(message)


def _in_file_directory(filename):
    return _dirname + '/' + filename


def _process_args():
    """ Process the arguments passed to the script """

    if args.mode == 'launch':
        if args.processes < 1:
            logger.error("Number of tor processes must be 1 or greater")
            sys.exit(1)

        if args.tor_control_port < args.tor_port + args.processes:
            args.tor_control_port = args.tor_port + args.processes

            logger.log("Initial control port conflict, changing to {}".format(args.tor_control_port))
    else:  # attach mode
        global _fatal_error_received

        if args.tor_path != 'tor':
            logger.error("--path requires --launch flag to be set")
            _fatal_error_received = True
        if args.tor_data_dir != '~/.torantula/data/tor':
            logger.error("-d requires --launch flag to be set")
            _fatal_error_received = True
        if args.processes != 1:
            logger.error("-n requires --launch flag to be set")
            _fatal_error_received = True

    args.tor_data_dir = expanduser(args.tor_data_dir)


class DomainProcessor:
    def __init__(self, tld_file="effective-tld-names.dat"):
        """
        Construct new DomainProcessor object

        :param tld_file: file of tlds to read
        """
        self._tld_names = dict()
        self._read_tld_names(tld_file)

    def get_second_level_domain(self, domain):
        """
        Gets the second-level domain of the given full domain. Ex: hello.world.example.com becomes example.com

        :param domain: domain to get second-level of
        :return: second-level domain of given full domain
        """
        for key in sorted(self._tld_names.keys(), reverse=True):
            if domain.endswith(tuple(self._tld_names[key])):
                return '.'.join(domain.split('.')[-(key + 2):])
        return domain

    def _read_tld_names(self, tld_file):
        """ Parses the tld_file """

        with open(_in_file_directory(tld_file), 'r', errors='ignore') as f:
            for line in f.readlines():
                if not (line.startswith('//') or line.startswith('#') or len(line) < 2):
                    num_dots = sum(1 for c in line if c == '.')

                    if num_dots not in self._tld_names:
                        self._tld_names[num_dots] = set()

                    self._tld_names[num_dots].add(line.strip())


def _launch_tor_thread(process_dict, launch_threads, index):
    """
    Launches a single Tor thread

    Method was factored out for readability
    """
    socks_port = args.tor_port + index
    control_port = args.tor_control_port + index
    password = binascii.hexlify(os.urandom(PASSWORD_LENGTH)).decode("utf-8")
    data_directory = args.tor_data_dir + str(index)

    thread = TorLauncher(process_dict, socks_port, control_port, password, data_directory)
    thread.daemon = True

    launch_threads.append(thread)

    thread.start()


def _launch_tor_processes(num_connections):
    """ Launches num_connections Tor processes and returns a dictionary of port:process containing each process """

    process_dict = {}
    launch_threads = []

    for i in range(num_connections):
        _launch_tor_thread(process_dict, launch_threads, i)

    for thread in launch_threads:
        thread.join()

        if not _fatal_error_received:
            _log_verbose("Tor listening on {}".format(thread.tor_process.get_port()))

    return process_dict


class TorLauncher(Thread):
    def __init__(self, process_dict, socks_port=args.tor_port, control_port=args.tor_control_port, control_password="",
                 data_directory=args.tor_data_dir):
        """
        Construct a new TorLauncher object.

        Run tor_launcher.start() to launch a new TorProcess in a new thread

        :param process_dict: dictionary of processes to add a launched TorProcess to
        :param socks_port: Socks port to run Tor on
        :param control_port: Control port to use with Tor
        :param control_password: Control password to secure the Tor control port with
        :param data_directory: Data directory for Tor
        """
        Thread.__init__(self)

        self.process_dict = process_dict
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self.data_directory = data_directory
        self.tor_process = None

    def run(self):
        """ Launches a new Tor Process. Adds it to process_dict with its key as the port it runs on """

        try:
            self.tor_process = TorProcess(self.socks_port,
                                          self.control_port,
                                          self.control_password,
                                          self.data_directory)

            self.tor_process.launch_process()

            if not _fatal_error_received:
                self.tor_process.connect_to_controller()

            self.process_dict[self.socks_port] = self.tor_process
        except socket.error as ex:
            raise ex
        except:
            traceback.print_exc()


class TorProcess:
    def __init__(self, socks_port=args.tor_port, control_port=args.tor_control_port, control_password="",
                 data_directory=args.tor_data_dir):
        """
        Create new TorProcess object

        :param socks_port: Tor's socks port
        :param control_port: Tor's control port
        :param control_password: Password for securing the Tor control port
        :param data_directory: Tor's data directory
        """
        self._control_port = control_port
        self._control_password = control_password
        self._data_directory = data_directory
        self._socks_port = socks_port

        self.controller = None
        self._tor_process = None

    def connect_to_controller(self):
        try:
            self.controller = Controller.from_port(port=self._control_port)
            self.controller.authenticate(password=self._control_password)
        except stem.SocketError:
            self.controller = None
            logger.warn("Could not connect to control port. Running without it")

    def launch_process(self):
        """
        Launch a new Tor process with this TorProcess' information

        Blocks until Tor fails or is finished setting itself up, so may want to run in its own thread
        """
        if not os.path.exists(self._data_directory):
            os.makedirs(self._data_directory)

        torrc = _in_file_directory("torrc")

        self._tor_process = subprocess.Popen([args.tor_path, "-f", torrc,
                                              "--SocksPort", str(self._socks_port),
                                              "--ControlPort", str(self._control_port),
                                              "--HashedControlPassword",
                                              TorProcess.hash_password(self._control_password),
                                              "--DataDirectory", str(self._data_directory)
                                              ], stdout=subprocess.PIPE)

        # Look for the string Tor outputs when it's finished setting up
        line = self._tor_process.stdout.readline()
        while b"Bootstrapped 100%: Done" not in line:
            global _fatal_error_received

            if line:
                _log_verbose("TOR {}: {}".format(self._socks_port, line.decode('UTF-8').strip()))

            # Looks for particular issue with data directory being in use
            if b"looks like another Tor process is running with the same data directory" in line:
                logger.error("TOR {}: Data directory already in use".format(self._socks_port))

                _fatal_error_received = True
                break

            # If the process has finished without printing the desired string
            if self._tor_process.poll():

                # Read and print everything, looking for some common errors to give constructive messages for
                for line in self._tor_process.stdout.readlines():
                    _log_verbose("TOR {}: {}".format(self._socks_port, line.decode('UTF-8').strip()))

                    if b"Address already in use" in line:
                        if str(self._socks_port).encode("UTF-8") in line:
                            logger.error("TOR {}: Socks port {} already in use"
                                         .format(self._socks_port, self._socks_port))
                        if str(self._control_port).encode("UTF-8") in line:
                            logger.error("TOR {}: Control port {} already in use"
                                         .format(self._socks_port, self._control_port))

                _fatal_error_received = True
                break

            line = self._tor_process.stdout.readline()
            time.sleep(.01)

    def get_control_port(self):
        return self._control_port

    def get_control_password(self):
        return self._control_password

    def get_port(self):
        return self._socks_port

    def get_exit_info(self, username):
        """
        Get IP and Country Code of the given circuit username

        :param username: username for the desired circuit
        :return: tuple with the ip address [0] and 2-letter country code [1] of the exit node
        """
        for circuit in self.controller.get_circuits():
            if circuit.status == stem.CircStatus.BUILT and circuit.socks_username == username:
                fp, nickname = circuit.path[-1]

                exit_relay = self.controller.get_network_status(fp, None)
                if exit_relay:
                    location = self.controller.get_info("ip-to-country/{}".format(exit_relay.address), 'unknown')
                    return exit_relay.address, location

        return "???.???.???.???", "??"

    def kill(self):
        self._tor_process.kill()

    @staticmethod
    def hash_password(password):
        """
        Get the hashed form of the password as Tor would accept it as a HashedControlPassword argument

        :param password: password to hash
        :return: string with the salt:hash as Tor returns it
        """
        tor_process = subprocess.Popen([args.tor_path, "--hash-password", str(password)], stdout=subprocess.PIPE)

        return tor_process.communicate()[0].decode('UTF-8').split('\n')[-2].strip()


class RoundRobinCommandHandler(soxy.CommandHandler):
    """
    Handles how requests are forwarded with the SOCKS proxy

    Dispatches requests to processes or circuits in a round-robin manner, depending on the domain or IP address
    of the target. All requests to the same second-level domain or IP address (with the given cidr mask) should go
    through the same circuit
    """
    _address_name_map = dict()
    _name_password_map = dict()
    _domain_processor = DomainProcessor()

    _circuit_names = args.processes * args.circuits + 1 if args.circuits > 0 else 2**32 - 1
    _last_name = 1

    def handle_connect(self):
        """
        Handle the connect request

        Dispatches requests to processes or circuits in a round-robin manner, depending on the domain or IP address
        of the target. All requests to the same second-level domain or IP address (with the given cidr mask) should go
        through the same circuit
        """
        dst_socket = None

        try:
            tor_port_num, dst_username, dst_password = self.get_route_details(self.dst_address)

            dst_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            dst_socket.set_proxy(socks.SOCKS5, "0.0.0.0", tor_port_num, username=dst_username, password=dst_password)

            dst_socket.connect((self.dst_address, self.dst_port))

            self.src_socket.settimeout(soxy.RESEND_TIMEOUT)
            dst_socket.settimeout(soxy.RESEND_TIMEOUT)

            self._send_tcp_success()

            if tor_processes[tor_port_num].controller:
                dst_exit_info = tor_processes[tor_port_num].get_exit_info(dst_username)
                logger.log('{}:{:5} <-> {:20} <-> {}'.format(self.src_info[0], self.src_info[1],
                           '{} ({})'.format(dst_exit_info[0], dst_exit_info[1].upper()), self.dst_address))
            else:
                logger.log('{}:{:5} <-> {}'.format(self.src_info[0], self.src_info[1], self.dst_address))

            soxy.Forwarder(self.src_socket, dst_socket).start()
            soxy.Forwarder(dst_socket, self.src_socket).run()

        except socks.ProxyError as e:
            self._send_message(soxy.STAT_GENERAL_ERROR)  # TODO more specific error code

            if "0x06" not in str(e.msg) and "0x01" not in str(e.msg):
                _warn_verbose('{} on {}:{:5} <-> {}:{}'
                              .format(e, self.src_info[0], self.src_info[1], self.dst_address, self.dst_port))
        finally:
            if dst_socket:
                dst_socket.close()

    def handle_bind(self):
        """ Tor doesn't support BIND, so neither do we """

        _warn_verbose('BIND received')
        self.handle_unsupported()

    def handle_udp(self):
        """ Tor doesn't support UDP, so neither do we """

        _warn_verbose('UDP received')
        self.handle_unsupported()

    @staticmethod
    def get_route_details(address):
        """
        Gets the details for routing the request to the given domain

        :param address: address to get routing details for
        :return: three-tuple where
            [0] -> The port of the tor instance to send this to
            [1] -> The username to use for Tor credentials
            [2] -> The password to use for Tor credentials
        """
        try:
            dict_address = str(ipaddress.ip_interface(str(address) + "/" + str(args.cidr_mask)).network.network_address)
        except ValueError:  # Is domain, not IP address
            dict_address = RoundRobinCommandHandler._domain_processor.get_second_level_domain(address)

        if dict_address in RoundRobinCommandHandler._address_name_map:
            name = RoundRobinCommandHandler._address_name_map[dict_address]
        else:
            name = RoundRobinCommandHandler._last_name
            RoundRobinCommandHandler._address_name_map[dict_address] = name

            RoundRobinCommandHandler._last_name = RoundRobinCommandHandler._last_name % RoundRobinCommandHandler._circuit_names + 1

        return args.tor_port + (name % args.processes), str(name), RoundRobinCommandHandler._get_nonce_from_name(name)

    @staticmethod
    def _get_nonce_from_name(name):
        """
        Get the "Password" for the SOCKS credentials from the corresponding username
        Randomly creates one if it doesn't exist already

        :param name: username of the SOCKS credentials to get the associated password for
        :return: password/nonce corresponding to the given username
        """
        if name in RoundRobinCommandHandler._name_password_map:
            return RoundRobinCommandHandler._name_password_map[name]
        else:
            password = str(binascii.hexlify(os.urandom(PASSWORD_LENGTH)))
            RoundRobinCommandHandler._name_password_map[name] = password
            return password


def _test_socks_port(port):
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "localhost", port)

    try:
        s.connect(("example.com", 80))  # Maybe find better domain?
    except socks.ProxyConnectionError:
        return False

    return True


def _print_fail_to_connect():
    if args.verbose:
        logger.error("Failed to connect to Tor")
    else:
        logger.error("Failed to connect to Tor. Run with -v argument for more info")
        

if __name__ == '__main__':
    proxy, tor_processes = None, None

    _process_args()

    try:
        if _fatal_error_received:
            _print_fail_to_connect()
            sys.exit(1)

        if args.mode == 'attach':
            tor_processes = dict()

            logger.log("Attaching socks port {} and control port {}".format(args.tor_port, args.tor_control_port))

            process = TorProcess(args.tor_port, args.tor_control_port, args.tor_control_password)
            process.connect_to_controller()

            tor_processes[args.tor_port] = process

            if not _test_socks_port(args.tor_port):
                _warn_verbose("Is Tor running? Is Tor using a control port? Try adding --launch argument")

                _fatal_error_received = True
        else:  # Launch mode
            logger.log("Launching {} Tor process{}...".format(args.processes, 'es' if args.processes != 1 else ''))

            tor_processes = _launch_tor_processes(args.processes)

        if _fatal_error_received:
            _print_fail_to_connect()
            sys.exit(1)

        proxy = soxy.Server(("localhost", args.port), RoundRobinCommandHandler)

        if not _fatal_error_received:
            logger.log("Listening on {}:{}".format(proxy.server_address[0], proxy.server_address[1]))

            try:
                proxy.serve_forever()
            except KeyboardInterrupt:
                pass

        if tor_processes:
            for tor_process in tor_processes.values():
                tor_process.kill()

    except Exception as e:
        if proxy:
            proxy.shutdown()
        raise e
