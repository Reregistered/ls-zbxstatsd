import re
from socket import AF_INET, SOCK_DGRAM, socket
import threading
import time
import types
import logging
import sqlite3
from zabbix_api import ZabbixAPI
from zbxsend import Metric, send_to_zabbix 
from collections import defaultdict

try:
    from setproctitle import setproctitle
except ImportError:
    setproctitle = None

from daemon import Daemon


__all__ = ['Server']

def getappidlist(zbxhost):
    global zbx_appid_dict 
    import configfile

    zapi = ZabbixAPI(server=configfile.url, log_level=2)
    zapi.login(configfile.username, configfile.password)

    applist = []
     
    if zbxhost not in zbx_appid_dict:
        logging.debug(zbxhost + " not in zbx_appid_dict")
        
        ### Get the hostid
        hostid = zapi.host.get({"filter":{"host":zbxhost},"output":"extend"})[0]['hostid']
        ### Loop through list "applications"
        for app in configfile.applications:
            ### Check if each application exists on server
            if zapi.application.exists({"name":app,"host":hostid}):
                ### If it exists, get the id and put it in as a string
                result = zapi.application.get({"filter":{"name":app, "hosts":[{"hostid":hostid}]}})[0]["applicationid"]
                applist.append(result)
            else:
                ### The item doesn't exist on the server.  Create it, then put the entry in the dict as a string
                result = zapi.application.create({"name":app,"hostid":hostid})["applicationids"][0]
                applist.append(result)
        ### Append the list to the global dict
        zbx_appid_dict[zbxhost].append(applist)

    ### Either way, now, we have it, send it back.

    return zbx_appid_dict[zbxhost]


def create_zbxitem(zbxhost, zbxkey, value):
    import configfile

    zapi = ZabbixAPI(server=configfile.url, log_level=2)
    zapi.login(configfile.username, configfile.password)
    
    name = "Metric " + zbxkey
        
    try:
        value = int(value)
        value_type = 3
    except:
        try:
            value = float(value)
            value_type = 0
        except:
            logging.error("Item type not integer or float type")
    appidlist = getappidlist(zbxhost)[0]
    hostid=zapi.host.get({"filter":{"host":zbxhost}})[0]["hostid"]
    interfaceid = zapi.hostinterface.get({"filter":{"hostid":hostid},"output":"extend"})[0]['interfaceid']
    ### type 2 is Zabbix trapper type
    itemObject = { 'hostid' : (hostid), 'interfaceid' : (interfaceid), 'history' : configfile.history, 'delay' : 0, 'name' : (name), 'key_' : zbxkey, 'type' : 2, 'value_type' : value_type, 'applications': appidlist } 
#    itemObject['applications'] = appidlist
    keytrunk = zbxkey.split('[')[0]
    try:
        keyindex = zbxkey.split('[')[1].strip(']')
    except:
        keyindex = ''
    
    if not keyindex == 'count':
        if keytrunk in configfile.units:
            itemObject['units'] = configfile.units[keytrunk]
        if keytrunk in configfile.formulas:
            itemObject['multiplier'] = 1
            itemObject['formula'] = configfile.formulas[keytrunk]
            ### Must be prepared to override the value_type if we're applying a float multiplier
            try:
                value = int(config.formulas[keytrunk])
                value_type = 3
            except:
                try:
                    value = int(config.formulas[keytrunk])
                    value_type = 3
                except:
                    logging.error("Formula not integer or float type")
            itemObject['value_type'] = 0

    zapi.item.create(itemObject)

def dbread(mydict):
    import configfile
    try:
        con = sqlite3.connect(configfile.dbfile)
        try:
            for row in con.execute('''select * from statsdiscovery'''):
                mydict[row[0]].append(row[1])
        except:
            err = 1
    except sqlite3.Error, e:
        print "Error %s:" % e.args[0]
    return mydict

def dbwrite(metrics):
    global zbx_item_dict 
    import configfile
    con = None
    
    try:
        con = sqlite3.connect(configfile.dbfile)
        cur = con.cursor()    
        try:
            cur.execute('''CREATE TABLE statsdiscovery (host text, itemkey text, UNIQUE (host,itemkey))''')
            con.commit() 
        except:
            err = 1
    
    except sqlite3.Error, e:
        print "Error %s:" % e.args[0]
        sys.exit(1)
    for m in metrics:
        ### Do the check to see if the key is in zbx_item_dict, 
        ### If it isn't, then do the dbwrite
        if m.key not in zbx_item_dict[m.host]:
            logging.debug("Key not in zbx_item_dict")
            zbx_item_dict[m.host].append(m.key)
            queryvalues = (m.host, m.key)
            try:
                cur.execute('select count(*) from statsdiscovery where host=? AND itemkey=?', queryvalues)
                result = cur.fetchone()
                logging.debug('Count of matching rows with host, key = ' + str(result[0]))
            except sqlite3.Error, e:
                print "Error %s:" % e.args[0]
            if result[0] < 1:
                ### The item may not exist on the server.  Create it first, then put the entry in the db table
                try:
                    create_zbxitem(m.host, m.key, m.value)
                    cur.execute('INSERT into statsdiscovery(host,itemkey) VALUES (?,?)', queryvalues)
                    con.commit()
                except sqlite3.Error, e:
                    print "Error %s:" % e.args[0]
            else:
                logging.debug('Already in database.  Ignoring.') 

    if con:
        con.close()

def _clean_key(k):
    return re.sub(
        '[^a-zA-Z_\-0-9\.\[\]]',
        '',
        k.replace('/','-').replace(' ','_')
    )

class Server(object):

    def __init__(self, pct_threshold=90, debug=False, zabbix_host='localhost', zabbix_port=10051, flush_interval=10000):
        self.buf = 1024
        self.flush_interval = flush_interval
        self.pct_threshold = pct_threshold
        self.zabbix_host = zabbix_host
        self.zabbix_port = zabbix_port
        self.debug = debug

        self.counters = {}
        self.timers = {}
        self.flusher = 0


    def process(self, data):
        ### Remove the namespace from the data stream.  We don't care in Zabbix.
        data = data.replace('logstash.', '',1)
        try:
            hostkey, val = data.split(':')
        except ValueError:
            logging.info('Got invalid data packet. Skipping')
            logging.debug('Data packet dump: %r' % data)
            return
        try:
            host, key = hostkey.split(';;')
            ### Just in case people decide to put the ;; delimiter on the host or the key side, we strip both
            host = host.rstrip('.')
            key = key.lstrip('.')
            ### Logstash swaps '.' for '_', but for Zabbix, we need this to be switched back (FQDN)
            host = host.replace('_', '.')
        except ValueError:
            logging.info('Got invalid host and/or key data. Skipping')
            logging.debug('Data packet dump: %r' % data)
            return
        key = _clean_key(key)
        sample_rate = 1;
        fields = val.split('|')

        item_key = '%s:%s' % (host, key)
        
        if (fields[1] == 'ms'):
            if item_key not in self.timers:
                self.timers[item_key] = []
            self.timers[item_key].append(float(fields[0] or 0))
        else:
            if len(fields) == 3:
                sample_rate = float(re.match('^@([\d\.]+)', fields[2]).groups()[0])
            if item_key not in self.counters:
                self.counters[item_key] = 0;
            self.counters[item_key] += float(fields[0] or 1) * (1 / sample_rate)

    def flush(self):
        global zbx_item_dict
        ts = int(time.time())
        stats = 0
        stat_string = ''
#        self.pct_threshold = 10
        
        metrics = []
        
        for k, v in self.counters.items():
            v = float(v) / (self.flush_interval / 1000)
            
            host, key = k.split(':',1)
            
            metrics.append(Metric(host, key, str(v), ts))

            self.counters[k] = 0
            stats += 1

        for k, v in self.timers.items():
            if len(v) > 0:
                v.sort()
                count = len(v)
                min = v[0]
                max = v[-1]

                mean = min
                max_threshold = max
                median = min

                if count > 1:
                    thresh_index = int(round(count*float(self.pct_threshold)/100))#count - int(round((100.0 - self.pct_threshold) / 100) * count)
                    max_threshold = v[thresh_index - 1]
                    total = sum(v[:thresh_index])
                    mean = total / thresh_index
                    
                    if count%2 == 0:
                        median = (v[count/2] + v[count/2-1])/2.0
                    else:
                        median = (v[count/2])

                self.timers[k] = []

                host, key = k.split(':', 1)
                metrics.extend([
                    Metric(host, key + '[mean]', mean, ts),
                    Metric(host, key + '[upper]', max, ts),
                    Metric(host, key + '[lower]', min, ts),
                    Metric(host, key + '[count]', count, ts),
                    Metric(host, key + '[upper_%s]' % self.pct_threshold, max_threshold, ts),
                    Metric(host, key + '[median]', median, ts),
                ])

                stats += 1

#        stat_string += 'statsd.numStats %s %d' % (stats, ts)

        dbwrite(metrics)
        send_to_zabbix(metrics, self.zabbix_host, self.zabbix_port)

        self._set_timer()

        if self.debug:
            print metrics

        
    def _set_timer(self):
        self._timer = threading.Timer(self.flush_interval/1000, self.flush)
        self._timer.start()

    def serve(self, hostname='', port=8126, zabbix_host='localhost', zabbix_port=2003):
        assert type(port) is types.IntType, 'port is not an integer: %s' % (port)
        addr = (hostname, port)
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.bind(addr)
        self.zabbix_host = zabbix_host
        self.zabbix_port = zabbix_port

        import signal
        import sys
        def signal_handler(signal, frame):
            self.stop()
        signal.signal(signal.SIGINT, signal_handler)

        self._set_timer()
        while 1:
            data, addr = self._sock.recvfrom(self.buf)
            self.process(data)

    def stop(self):
        self._timer.cancel()
        self._sock.close()


class ServerDaemon(Daemon):
    def run(self, options):
        if setproctitle:
            setproctitle('zbxstatsd')
        server = Server(pct_threshold=options.pct, debug=options.debug, flush_interval=options.flush_interval)
        server.serve(options.name, options.port, options.zabbix_host,
                     options.zabbix_port)


def main():
    import sys
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='debug mode', default=False)
    parser.add_argument('-n', '--name', dest='name', help='hostname to run on', default='')
    parser.add_argument('-p', '--port', dest='port', help='port to run on', type=int, default=8126)
    parser.add_argument('--zabbix-port', dest='zabbix_port', help='port to connect to zabbix on', type=int, default=10051)
    parser.add_argument('--zabbix-host', dest='zabbix_host', help='host to connect to zabbix on', type=str, default='localhost')
    parser.add_argument('-l', dest='log_file', help='log file', type=str, default=None)
    parser.add_argument('-f', '--flush-interval', dest='flush_interval', help='interval between flushes', type=int, default=10000)
    parser.add_argument('-t', '--pct', dest='pct', help='stats pct threshold', type=int, default=90)
    parser.add_argument('-D', '--daemon', dest='daemonize', action='store_true', help='daemonize', default=False)
    parser.add_argument('--pidfile', dest='pidfile', action='store', help='pid file', default='/tmp/pystatsd.pid')
    parser.add_argument('--restart', dest='restart', action='store_true', help='restart a running daemon', default=False)
    parser.add_argument('--stop', dest='stop', action='store_true', help='stop a running daemon', default=False)
    options = parser.parse_args(sys.argv[1:])
    logging.basicConfig(level=logging.DEBUG if options.debug else logging.WARN,
                        stream=open(options.log_file, 'w') if options.log_file else sys.stderr)

    daemon = ServerDaemon(options.pidfile)
    if options.daemonize:
        daemon.start(options)
    elif options.restart:
        daemon.restart(options)
    elif options.stop:
        daemon.stop()
    else:
        daemon.run(options)
        
### Define global variable that contains a cache of all host/key pairs
zbx_item_dict = dbread(defaultdict(list))
zbx_appid_dict = defaultdict(list)

if __name__ == '__main__':
    main()
