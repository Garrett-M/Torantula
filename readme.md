# Torantula

Torantula is a tool for isolating streams with Tor.

## Requirements

* Tor
* Python3
* Linux (MacOS will probably work, too, but I haven't tested it)

## Installation

``` [sudo] python3 setup.py install ```

## Usage

### Bind to a Tor instance running on port 9050 (The default), and run Torantula's proxy server on port 9000

``` ./torantula.py 9000 ```

### Launch own instance(s) of Tor

``` ./torantula.py --launch ```

### Use finite number of circuits (Per process)

``` ./torantula.py -c 16 ```

### Launch with multiple Tor processes

``` ./torantula.py -n 8 --launch ```

### Use a different CIDR suffix (helpful if connecting to sequential IPs)

``` ./torantula.py --cidr 32 ```

### Download stuff super fast through Tor (you monster)

``` ./torantula.py -n 8 -c 8 --launch ```
