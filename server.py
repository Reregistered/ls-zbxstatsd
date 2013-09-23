import re
from socket import AF_INET, SOCK_DGRAM, socket
import threading
import time
import types
import logging
import sqlite3
from zoop import *
import configfile
from zbxsend import Metric, send_to_zabbix 

try:
    from setproctitle import setproctitle
except ImportError:
    setproctitle = None

from daemon import Daemon


__all__ = ['Server']



class CachingZbxItemCreator:
    """Class to contain SQLite3 db methods, which maintain create zabbix items """
    def __init__(self, api):
        """Initiate instance by creating a connection to the db and creating it and the table if they don't already exist"""
        #import configfile
        self.api = api
        self.app_cache = { }
        self.key_cache = {}
        self.applications = configfile.applications
        self.dbfile = configfile.dbfile
        self.formulas = configfile.formulas
        self.history = configfile.history
        self.itemrefresh = configfile.itemrefresh
        self.units = configfile.units

        self.con = None
        try:
            self.con = sqlite3.connect(self.dbfile)
            self.cur = self.con.cursor()    
            try:
                self.cur.execute('''CREATE TABLE metric_tokens (host text, key_ text, timestamp integer, UNIQUE (host,key_))''')
                self.con.commit() 
            except:
                # There's no reason to complain if it fails to create.
                # It should mean that it is already there, which is fine
                pass
        except sqlite3.Error, e:
            logging.debug("Error:" + e.args[0])
            sys.exit(1)
        # Close connection when done
        self.disconnect()
        self.init_key_cache()


    def connect(self):
        """Establish a connection to the db, and a cursor"""
        self.con = None 
        try:
            self.con = sqlite3.connect(self.dbfile)
            logging.debug("self.dbfile = " + self.dbfile)
            self.cur = self.con.cursor()    
        except sqlite3.Error, e:
            logging.debug("Error:" + e.args[0])
            sys.exit(1)


    def disconnect(self):
        """Close db connection if one exists"""
        if self.con:
            self.con.close()


    def init_key_cache(self):
        self.connect()
        self.cur.execute('''select * from metric_tokens''')
        mydict = {}
        try:
            for row in self.cur.fetchall():
                if not mydict.has_key(row[0]):
                    mydict[row[0]] = {}
                mydict[row[0]][row[1]] = row[2]
        except:
            # There's no reason to complain if it fails
            # If there are no results, then we just create an empty dict
            pass
        self.key_cache.update(mydict)
        self.disconnect()
        


    def app_cached(self, host):
        """Return True or False regarding host's existing in the cache"""
        #logging.debug("app_cache on next line:")
        #logging.debug(self.app_cache)
        if host not in self.app_cache:
            logging.debug(host + " not in self.app_cache")
            return False
        else:
            return True


    def key_cached(self, key_, host):
        """Return True or False regarding key_'s existing in the cache"""
        try: 
            if key_ in self.key_cache[host]:
                return True
            else:
                return False
        except:
            return False


    def get_timestamp(self, key_, host):
        """Fetch timestamp from row with matching key_ & host"""
#        self.connect()
        getvalues = (host, key_)
        try:
            self.cur.execute('select timestamp from metric_tokens where host=? AND key_=?', getvalues)
            retval = self.cur.fetchone()[0]
        except sqlite3.Error, e:
            logging.debug("Error:" + e.args[0])
            retval = False
#        self.disconnect()
        return retval


    def insert(self, setvalues):
        """Execute insert statement"""
#        self.connect()
        try:
            self.cur.execute('INSERT into metric_tokens(host,key_,timestamp) VALUES (:myhost, :mykey_, :myts)', setvalues)
            self.con.commit()
            retval = True
        except sqlite3.Error, e:
            logging.debug("Error:" + e.args[0])
            retval = False
#        self.disconnect()
        return retval
        
    def update(self, setvalues):
        """Update timestamp"""
#        self.connect()
        try:
            self.cur.execute('UPDATE metric_tokens SET timestamp ==:myts where host ==:myhost and key_ ==:mykey_', setvalues)
            self.con.commit()
            retval = True
        except sqlite3.Error, e:
            logging.debug("Failed to update database.  Error: " + e.args[0])
            retval = False
#        self.disconnect()
        return retval

    def getappidlist(self, hostapi):
        """Get a list of appids from the configfile and validate them agaist the Zabbix API.  Create if not existent""" 
        if not self.app_cached(hostapi["hostid"]):
            ### Loop through list "applications"
            applist = []
            for app in self.applications:
                ### Check if each application exists on server
                if hostapi.appexists(app):
                    ### If it exists, get the id and put it in as a string
                    applist.append(hostapi.getappid(app))
                else:
                    ### The item doesn't exist on the server.  Create it, then put the entry in the dict as a string
                    applist.append(hostapi.createapp(app))
            ### The [host] index gets the applist
            self.app_cache[hostapi["host"]] = applist

    def recast(self, value):
        """Recast strings as float or int"""
        try:
            ret = int(value)
        except ValueError:
            ret = float(value)
        return ret  

    def set_value_type(self, itemObject, key_, value):
        """Map value type from provided value"""
        value = self.recast(value)
        if type(value) == type(int()):
            value_type = 3
        elif type(value) == type(float()):
            value_type = 0
        else:
            logging.error("Item type not integer or float type")
            print "Fail: Formula not integer or float type"
            sys.exit(2)

        ### Override for unit/formula modifiers
        keytrunk = key_.split('[')[0]
        try:
            keyindex = key_.split('[')[1].strip(']')
        except:
            keyindex = ''
        
        if not keyindex == 'count':
            if keytrunk in self.units:
                itemObject['units'] = self.units[keytrunk]
            if keytrunk in self.formulas:
                itemObject['multiplier'] = 1
                itemObject['formula'] = self.formulas[keytrunk]
                logging.error("multiplier = " + str(itemObject['multiplier']) + " and formula = " + str(itemObject['formula']))
                ### Must be prepared to override the value_type if we're applying a float multiplier
                formulavalue = self.recast(self.formulas[keytrunk])
                if type(formulavalue) == type(int()):
                    value_type = 3
                elif type(formulavalue) == type(float()):
                    value_type = 0
                else:
                    logging.error("Formula not integer or float type")
                    sys.exit(2)
        return value_type


    def zbxitemcheck(self, host, key_, value):
        
        zhost = self.api.host() 
        zhost.get(host=host)
        if not zhost.exists():
            errormsg = "Error! Hostname " + host + " does not exist"
            print errormsg
            logging.debug(errormsg)
            sys.exit(2)

        zitem = self.api.item()
        zitem["key_"] = key_
        zitem["hostid"] = zhost["hostid"]
        if zitem.exists():
            # This is a good thing!  We don't have to create it!
            logging.debug("Item with key " + key_ + " exists!")
            pass
        else: 
            logging.debug("Item with key " + key_ + " does not exist!")
            zitem["value_type"] = self.set_value_type(zitem, key_, value)
    
            ziface = self.api.hostinterface()
            ziface.get(hostid=zhost["hostid"])
            zitem["interfaceid"] = ziface.agent()
    
            zitem["history"] = self.history
            zitem["delay"] = 0
            zitem["name"] = "Metric " + key_
            # getappidlist will populate self.app_cache[host]
            self.getappidlist(zhost)
            zitem["applications"] = self.app_cache[host]
            ### type 2 is Zabbix trapper type
            zitem["type"] = 2
            # We can log the result this way.  It should fail if unsuccessful, but otherwise it should quietly work.
            result = zitem.create()


    def process(self, metrics):
        """Process metrics, caching, dbwriting, item creation, etc."""
        self.connect()
        retval = True
        now = int(time.time())
        for m in metrics:
            if not 'zabbix.host' in m.host:
                setvalues = { "myhost" : m.host, "mykey_" : m.key, "myts" : now }
                ### Do the check to see if the key is cached
                ### If it isn't, then do the insert
                if not self.key_cached(m.key, m.host):
                    logging.debug("m.key: " + m.key + " not in self.key_cache")
                    ### Create item in zabbix
                    self.zbxitemcheck(m.host, m.key, m.value)
                    retval = self.insert(setvalues)
                elif self.key_cache[m.host][m.key] < (now - self.itemrefresh):
                    ### The timestamp is too old, so we'll update.
                    ### Verify item in zabbix, if fails, recreate
                    self.zbxitemcheck(m.host, m.key, m.value)
                    retval = self.update(setvalues)
                    # Update caches
                    logging.debug('Already in database.  Ignoring.') 
                else:
                    # It's cached, but the timestamp is new enough to skip
                    logging.debug("Timestamp too new for another db write for " + m.host + ":" + m.key + " ...")
                    pass
        self.disconnect()
        if retval is True:
            try:
                # In either case, if we were successful, update the cache
                self.key_cache[m.host][m.key] = now
            except:
                # Variable m may not yet exist
                pass
        return retval

    


def _clean_key(k):
    return re.sub(
        '[^a-zA-Z_\-0-9\.\[\]]',
        '',
        k.replace('/','-').replace(' ','_')
    )

class Server(object):
    def __init__(self, pct_threshold=90, debug=False, zabbix_host='localhost', zabbix_port=10051, flush_interval=10000, api=None):
        #import configfile
        self.buf = 1024
        self.flush_interval = flush_interval
        self.pct_threshold = pct_threshold
        self.zabbix_host = zabbix_host
        self.zabbix_port = zabbix_port
        self.debug = debug
        self.timestamp = int(time.time())
        self.counters = {}
        self.timers = {}
        self.flusher = 0
        self.api = api
        if not self.api:
            print "api not defined.  Exiting"
            sys.exit(2)

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
        ts = int(time.time())
        stats = 0
        stat_string = ''
#        self.pct_threshold = 10
        
        metrics = []
        
        for k, v in self.counters.items():
            v = float(v) / (self.flush_interval / 1000)
            
            host, key = k.split(':',1)
            # Catch the case where an improper host is passed.
            if not 'zabbix.host' in host:
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
                # Catch the case where an improper host is passed.
                if not 'zabbix.host' in host:
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

        if (ts - self.timestamp) > 1800:
            # Guarantee we can still use self.api, if not, use the connect method
            version = self.api.version()
            if version == 0:
                self.api.connect()
            else:
                # If we get a version, we're good.
                pass
            # Reset self.timestamp
            self.timestamp = ts
        # Use our instance of class CachingZbxItemCreator, then send the metrics there
        ItemCreator = CachingZbxItemCreator(self.api)
        ItemCreator.process(metrics)
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
    #import configfile
    api = zoop(url=configfile.url, username=configfile.username, password=configfile.password, logLevel="DEBUG", logfile=configfile.logfile)
    def run(self, options):
        if setproctitle:
            setproctitle('ls-zbxstatsd')
        server = Server(pct_threshold=options.pct, debug=options.debug, flush_interval=options.flush_interval, api=ServerDaemon.api)
        server.serve(options.name, options.port, options.zabbix_host,
                     options.zabbix_port)


def main():
    import sys
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='debug mode', default=configfile.debug)
    parser.add_argument('-n', '--name', dest='name', help='hostname to run on', default=configfile.daemon_host)
    parser.add_argument('-p', '--port', dest='port', help='port to run on', type=int, default=configfile.daemon_port)
    parser.add_argument('--zabbix-port', dest='zabbix_port', help='port to connect to zabbix on', type=int, default=configfile.zabbix_port)
    parser.add_argument('--zabbix-host', dest='zabbix_host', help='host to connect to zabbix on', type=str, default=configfile.zabbix_host)
    parser.add_argument('-l', dest='log_file', help='log file', type=str, default=configfile.logfile)
    parser.add_argument('-f', '--flush-interval', dest='flush_interval', help='interval between flushes', type=int, default=configfile.flush_interval)
    parser.add_argument('-t', '--pct', dest='pct', help='stats pct threshold', type=int, default=configfile.percentage)
    parser.add_argument('-D', '--daemon', dest='daemonize', action='store_true', help='daemonize', default=False)
    parser.add_argument('--pidfile', dest='pidfile', action='store', help='pid file', default=configfile.pidfile)
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


if __name__ == '__main__':
    main()
