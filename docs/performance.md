# Performance optimizations

In the default configuration you have got the maximum flexibility. To achieve this every element for the address and for the network arrays is parsed and a new IP-object is created.

```
  cidr {
    address => [ "%{ipfield}", "%{otheripfield}" ]
    network => [ "%{netfield1}", "%{netfield2}", "10.0.0.0/8" ]
    add_tag => [ "local" ]
  }
```

In the above configuration example five new IP Objects are generated and five interpretations are needed for every event. 

## avoid ```event.sprintf```

One way to increase the performance is to disable the interpretation of fields. This optimization can be used if the ip and/or network is stored in an event and no further interpretation is needed.

```
  cidr {
    ipeventfield => true
    neteventfields => true
    address => [ "ipfield", "otheripfield" ]
    network => [ "netfield1", "netfield2" ]
    add_tag => [ "local" ]
  }
```


## avoid ```IPAddr.new```

Reducing the amount of newly created IPAddr-objects is the second method to process more events per time.

```
  cidr {
    ipeventfield => true
    netusesprintf => false
    address => [ "ipfield", "otheripfield" ]
    network => [ "fe80::/64", "192.168.0.0/16", "10.0.0.0/8" ]
    add_tag => [ "local" ]
  }
```

This creates a pre allocated array for the networks.

## Testenvironment

To messure the performance of the three different configurations the configfiles ```noopti.conf```, ```ipeventgield.conf``` and ```ipeventnetasis.conf``` where used. Logstash was called via

```sh
time taskset -c 0,1 ./bin/logstash -w 2 --quiet -f <config>  > <logfile>
```

The command ```taskset``` was used to limit the java-process to CPU0 and CPU1. With two worker processes and one generator process, the process is bound by CPU and we can messure time and rate.

The generator did produce 800,000 messages. Where 50% are local ips, 25% are remote and the remaining 25% are not an ip at all
```
  generator {
    count => 200000
    lines => [
      "192.168.1.100",
      "123.123.123.123",
      "foobar",
      "fe80::1234"
    ]
    threads => 1
```

## Results:

Depending on your configuration performance can be improved. The used examples gives round about 5% higher rates if the ip or net is directly stored in an eventfield and the plugin is informed about this. Using static values for network or address provides an additional speedup of about 25%

### noopti.conf

Output of ```time```
```
real	5m28.272s
user	10m9.767s
sys	0m20.420s
```

1 minute rates:
```
"local.rate_1m" => 1316.2063485793506,
"remote.rate_1m" => 658.1567296674931,
"not_an_ip.rate_1m" => 658.130769472656,
```

5 minutes rates
```
"local.rate_5m" => 931.7582029730767,
"remote.rate_5m" => 465.6396516103816,
"not_an_ip.rate_5m" => 465.77567824123196,
```

### ipeventfield.conf

Output of ```time```
```
real	5m10.988s
user	9m36.877s
sys	0m19.023s
```

1 minute rates:
```
"local.rate_1m" => 1391.8872496231136,
"remote.rate_1m" => 695.9802201234398,
"not_an_ip.rate_1m" => 695.9925526288816,
```

5 minutes rates:
```
"local.rate_5m" => 964.8029165471421,
"remote.rate_5m" => 482.37929835267477,
"no_an_ip.rate_5m" => 482.6969924754552,

### ipeventnetasis.conf

Output of time:
```
real	4m14.988s
user	7m53.913s
sys	0m16.950s
```

1 minute rates:
```
"local.rate_1m" => 1703.012042927653,
"remote.rate_1m" => 851.5016401218863,
"not_an_ip.rate_1m" => 851.5037681137894,
```

5 minutes rates:
```
"local.rate_5m" => 1108.284932966118,
"remote.rate_5m" => 554.0214334265335,
"not_an_ip.rate_5m" => 554.0171842930413,
```



