# Simple HTTP Redirect

## My Configuration

- Controller is running on Windows in PyCharm while I'm testing.
- I am using a S4112F-ON
- I am using a Ryu OpenFlow controller

### Switch Version Info

    OS10(config-openflow-switch)# do show version
    Dell EMC Networking OS10 Enterprise
    Copyright (c) 1999-2020 by Dell Inc. All Rights Reserved.
    OS Version: 10.5.1.3
    Build Version: 10.5.1.3.190
    Build Time: 2020-06-19T21:48:07+0000
    System Type: S4112F-ON
    Architecture: x86_64
    Up Time: 00:34:13


### Python Version

    C:\Users\grant\Documents\SimpleRedirect>python --version
    Python 3.8.3

### Ryu Version

    C:\Users\grant\Documents\dummycontroller>ryu --version
    ryu 4.32

## Setup

### Setup Controller

    pip install -r requirements.txt

### Setup OpenFlow on the Switch

#### Enable OpenFlow

On the switch run:

    OS10# configure terminal
    OS10(config)# openflow
    OS10(config-openflow)# mode openflow-only
    Configurations not relevant to openflow mode will be removed from the startup-configuration and system will be rebooted. Do you want to proceed? [confirm yes/no]:yes

#### Configure Management

    OS10(conf-if-ma-1/1/1)# interface mgmt 1/1/1
    OS10(conf-if-ma-1/1/1)# ip address <SOME MANAGEMENT IP>/24
    OS10(conf-if-ma-1/1/1)# no shutdown
    OS10(conf-if-ma-1/1/1)# exit

#### Configure OpenFlow Controller

    OS10# configure terminal
    OS10(config)# openflow
    OS10(config-openflow)# switch of-switch-1
    OS10(config-openflow-switch)# controller ipv4 <YOUR_CONTROLLER_IP> port 6633
    OS10(config-openflow-switch)# protocol-version 1.3
    OS10(config-openflow-switch)# no shutdown
    
**WARNING** The no shutdown is important. It defaults to shutdown.

## Running the Code

Run `python main.py`

## Helpful Notes

- I currently have the controller to remove any existing flows on startup - if you don't want this remove line 259
- You will need to update the IP address you want to redirect to on port 302
- You will need to update the physical port to which you want to output on line 308
- I have included an example of how to extend the Ryu API. On line 408 begins a function I wrote which will allow you to get a mapping between OpenFlow's logical port numbers and their physical names
    - Example:
    
            curl -X GET http://192.168.1.6:8080/ryu_app/getports/150013889521536
            [{"hw_addr": "88:6f:d4:98:a7:81", "name": "eth1/1/1", "openflow_port": 1}, {"hw_addr": "88:6f:d4:98:a7:82", "name": "eth1/1/2", "openflow_port": 5}, {"hw_addr": "88:6f:d4:98:a7:83", "name": "eth1/1/3", "openflow_port": 9}, {"hw_addr": "88:6f:d4:98:a7:84", "name": "eth1/1/4", "openflow_port": 13}, {"hw_addr": "88:6f:d4:98:a7:85", "name": "eth1/1/5", "openflow_port": 17}, {"hw_addr": "88:6f:d4:98:a7:86", "name": "eth1/1/6", "openflow_port": 21}, {"hw_addr": "88:6f:d4:98:a7:87", "name": "eth1/1/7", "openflow_port": 25}, {"hw_addr": "88:6f:d4:98:a7:88", "name": "eth1/1/8", "openflow_port": 29}, {"hw_addr": "88:6f:d4:98:a7:89", "name": "eth1/1/9", "openflow_port": 33}, {"hw_addr": "88:6f:d4:98:a7:8a", "name": "eth1/1/10", "openflow_port": 37}, {"hw_addr": "88:6f:d4:98:a7:8b", "name": "eth1/1/11", "openflow_port": 41}, {"hw_addr": "88:6f:d4:98:a7:8c", "name": "eth1/1/12", "openflow_port": 45}, {"hw_addr": "88:6f:d4:98:a7:8d", "name": "eth1/1/13", "openflow_port": 49}, {"hw_addr": "88:6f:d4:98:a7:91", "name": "eth1/1/14", "openflow_port": 53}, {"hw_addr": "88:6f:d4:98:a7:95", "name": "eth1/1/15", "openflow_port": 57}, {"hw_addr": "88:6f:d4:98:a7:81", "name": "of-switch0", "openflow_port": 4294967294}]
    - You will need to update the number at the end with your switch's DPID
- This code doesn't actually add any OpenFlow rules to the switch.
    - With OpenFlow you typically have OpenFlow match rules and if a packet matches a match entry, then a specified action is taken
        - Different actions are defined [here](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#action-structures)
        - Flow match structures are defined [here](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-match-structure)
        - Here is an example of a flow match structure for HTTP:
        
                match_in = parser.OFPMatch(
                    eth_type=int("800", 16),  # This is a prerequisite for matching against IPv4 packets
                    ip_proto=6,  # This is a prerequisite for matching against TCP segments
                    tcp_src=80)
                match_out = parser.OFPMatch(
                    eth_type=int("800", 16),
                    ip_proto=6,  # This is TCP,
                    tcp_dst=80)
                    
        - **Warning** You must provide the `eth_type` and `ip_proto` for flow matches or OpenFlow will reject your match structure.
- For troubleshooting OpenFlow I recommend using Wireshark on the controller looking for protocol `openflow_v4`. You can see any of the OpenFlow related messages and dissect them. 