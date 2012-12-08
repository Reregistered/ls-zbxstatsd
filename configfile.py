### Zabbix API
url = "http://www.example.com/zabbix"
username = "username"
password = "password"

### Host/Key pairing database
dbfile = '/tmp/zbxstatsd.db'

### Zabbix Item Constants
applications = [ "Log Metrics" ]
history = 30
units = { "apache.bytes" : "B", "apache.duration" : "s" }
formulas = { "apache.duration" : "0.000001" }
