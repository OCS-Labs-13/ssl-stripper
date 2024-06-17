# SSL Stripper
Automated tool to establish a man-in-the-middle (MIM) attack on a local network and strip SSL from spoofed HTTPS traffic.

This tool was made as part of a project for the course "2IC80 - Laboratory on Offensive Computer Security" at Eindhoven University of Technology (TU/e).

### Group 13
* Habeeb Mohammed - 1582143
* Kevin Koorneef - 1665944
* Austin Roose - 1682784
* Nathan Stork - 1462042

## Usage
Run main.py with necessary and optional options using the following command:
```python3 main.py [options]```.

### Options
* `-t <target>`: Target IP address to ARP poison. **Required**.
* `-g <gateway>`: Gateway IP address to ARP poison. _Default: known gateway IP of machine_.
* `-aI <interval>`: Interval between ARP requests in seconds. _Default: 30_.
* `-aC`: Ignore ARP cache when looking up MAC addresses of the target.
* `-d <file>`: File containing DNS hosts to spoof. Leave empty to disable DNS spoofing.
* `-dT <target>`: Target IP address to redirect DNS requests to. _Default: own IP_.
* `-sD`: Disable SSL stripping. _Default: false_.
* `-sL`: Disable logging of SSL requests. _Default: false_.
* `-sP <port>`: Port to listen for spoofed webserver traffic. _Default: 80_.

### Video
A video demonstration of the tool can be found [here](https://youtu.be/).

## Development
### Dependencies
It's required to update the requirements.txt file with the latest dependencies whenever new packages or libraries are introduced during development.
To do this first install `pipreq` by running the following command: ```pip install pipreqs```.
Then run ```pipreqs --force``` in the project's root directory to overwrite the existing requirements.txt file.

### Installation
Run the following command to install the required packages using pip:
```pip install -r requirements.txt```.
