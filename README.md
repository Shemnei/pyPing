A pure python implementation of ping.
======

Requires Python 3.5.
Must be run with root/administrator privileges.

Can be used as script/standalone or in other projects.

```python
 ping(host: str, *, payload_size: int=DEFAULT_PAYLOAD_SIZE, count: int=
    DEFAULT_COUNT, timeout: float=DEFAULT_TIMEOUT, quiet: bool=False, debug: bool=False) -> PingResult:

 PingResult = collections.namedtuple("PingResult",["send", "received", "lost",
                                "loss_per", "min", "max", "avg", "raw_times"])
```

Where:
 - host: Host
 - payload_size: pure size in bytes (without 8byte ICMP Header)
 - count: How often to ping
 - timeout: How long to wait for each response
 - quiet: If true print results
 - debug: If true print extra information about received IP/ICMP Header

Returns:
 - send: How many ICMP Echo-Requests where send
 - received: How many ICMP Echo-Requests where received
 - lost: How many ICMP Echo-Requests where lost
 - loss_per: Loss percentage
 - min: Shortest approx. RTT
 - max: Longest approx. RTT
 - avg: Average approx. RTT
 - raw_times: list of all times (None if packet timed out)

All times are in milli-seconds.

Credits:
- https://github.com/samuel/python-ping/blob/master/ping.py
- http://www.binarytides.com/raw-socket-programming-in-python-linux