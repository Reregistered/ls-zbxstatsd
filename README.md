Introduction
------------

ls-zbxstatsd is a fork of pistolero's zbx-statsd, which is a clone of Etsy's statsd and Steve Ivy's py-statsd.  It is designed to accept statsd output from logstash and output to Zabbix for stats collection and graphing.

Dependencies:

* zbxsend
	- PyPi: http://pypi.python.org/pypi/zbxsend/0.1.4
	- https://github.com/pistolero/zbxsend
	- Will work with just zbxsend.py in same local directory
* zoop 
	- https://github.com/untergeek/zoop.git
	- Object model for Zabbix that uses the Zabbix Python API listed below
* Zabbix Python API
	- https://github.com/gescheit/scripts.git
	- Will work with just zabbix_api.py in same local directory
* SQLite3 Python module
	- Most package managers will handle this :)
* Assorted python modules
	- argparse
	- simplejson
 

Features:
---------

* Automatic item creation
	- Will use API calls to automatically create items with:
		- Application Name
		- History
		- Per key/trunk Units (e.g. s for seconds, B for bytes, etc).
		- Per key/trunk Value multiplier (e.g. 0.001 for milliseconds to seconds)

* Running table of host/key pairings
	- A python dictionary of all known host/key pairings is compared when new values come in.  No unnecessary API calls.
	- Stored values from db are added at start-up time.

* SQLite3 database stores host/key pairings
	- Stored values are loaded into running table at start-up time.
	- As new values are added to the running table, they are also written to the db.  

* Configuration file directives
	- API login credentials
	- SQLite3 Host/Key pairing database file path.  This prevents attempted re-add of already created items on startup.
	- Zabbix application name

* Works with Zabbix proxy for stats collection
	- May need to wait for proxy to pick up new item configuration, based on zabbix_proxy.conf settings, before new values will show up.
	- Still need access to the API to create items, so this won't work in a completely firewalled/isolated environment
	

Attribution:
------------

* Logstash
	- https://github.com/logstash/logstash/
* zbx-statsd
	- https://github.com/pistolero/zbx-statsd/
* pystatsd
	- https://github.com/sivy/py-statsd/
* Statsd 
    - code: https://github.com/etsy/statsd
    - blog post: http://codeascraft.etsy.com/2011/02/15/measure-anything-measure-everything/

Usage:
------

Note: The default value for PORT is 8126, rather than the normal statsd value of 8125.

$ python server.py --help
usage: server.py [-h] [-d] [-n NAME] [-p PORT] [--zabbix-port ZABBIX_PORT]
                 [--zabbix-host ZABBIX_HOST] [-l LOG_FILE] [-f FLUSH_INTERVAL]
                 [-t PCT] [-D] [--pidfile PIDFILE] [--restart] [--stop]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           debug mode
  -n NAME, --name NAME  hostname to run on
  -p PORT, --port PORT  port to run on
  --zabbix-port ZABBIX_PORT
                        port to connect to zabbix on
  --zabbix-host ZABBIX_HOST
                        host to connect to zabbix on
  -l LOG_FILE           log file
  -f FLUSH_INTERVAL, --flush-interval FLUSH_INTERVAL
                        interval between flushes
  -t PCT, --pct PCT     stats pct threshold
  -D, --daemon          daemonize
  --pidfile PIDFILE     pid file
  --restart             restart a running daemon
  --stop                stop a running daemon

Typical launch command:
$ python server.py -D -n ls-zbxstatsd.example.com --zabbix-host zabbix-server.example.com -l /path/to/logfile.log



Logstash Configuration:
-----------------------

Logstash statsd information can be found here: http://logstash.net/docs/1.1.5/outputs/statsd

Note: Do not alter the namespace!  This script expects the default "logstash."  The code could be hacked to be namespace independent, but isn't at present.

Instructions:

sender: In this example a pre-existing field called "zabbix_host" is used.  This can be a hard-coded string or a field value.  In any case, it MUST be an existing host in Zabbix, and it MUST have the double semicolon post-pended.
The reason for this is that period delimiting doesn't work if your Zabbix host names are FQDNs.  How will the script know?  Double semicolons.  Miss this detail and the script will not work.

DOUBLE SEMICOLONS.  'nuff said.

The Zabbix key names will be the fields you specify here, e.g. "apache.bytes", "apache.status[200]" (or any other valid HTTP response code), "apache.duration"

Example:
  statsd {
    type => "apache"
    count => [ "apache.bytes", "%{bytes}" ]
    increment => "apache.status[%{status}]"
    timing => [ "apache.duration", "%{duration}" ]
    sender => "%{zabbix_host};;" # DOUBLE SEMICOLONS.  You have been warned :)
    host => "statsd.example.com" # The host where ls-zbxstatsd will be running
    port => 8126
  }


ls-zbxstatsd Configuration:
---------------------------

configfile.py is imported like a standard python module, rendering all of its values as regular variables in the context they were imported into.

### Zabbix API
url = "http://www.example.com/zabbix"
username = "username"
password = "password"

### Host/Key pairing database
dbfile = '/tmp/zbxstatsd.db'

### Zabbix Item Constants
applications = ["Log Metrics" ]
history = 30
units = { "apache.bytes" : "B", "apache.duration" : "s" }
formulas = { "apache.duration" : "0.000001" }

The units and formulas dictionaries allow for per zabbix-key item differentiation, e.g. duration is in microseconds in the apache output, so I need to set the multiplier to 0.000001 and set units to "s" for seconds.  Have more keys?  Add them here.
