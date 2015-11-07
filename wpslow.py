# DESCRIPTION
# 		wpslow - a slow wordpress plugin vulnurability scanner for pwning Bluehost/Dreamhost WAF (Web Application Firewall)
#		by using random timing for requests and random user-agents. 
#
# INSTALL 
#		copy into your wpscan folder 
# USAGE 
#		$ python wpslow.py targeturl:port minpause maxpause 
#
# 			:port is optional
# 			minpause and maxpause are delays between requests in seconds
#
# EXAMPLES 
#		$ python wpslow.py localhost:8000 2 5
#		$ python wpslow.py wordpress.com 2 5
#
#
#
# DEPENDENCIES 
#		wpscan plugins.json vulnerable plugin list
#
# NOTES
#		By default this script only looks for the plugins tagged 'popular' by wpscan to speed things up
#		
#

import sys
import math
import json
import httplib 
from random import choice
from random import randint
from time import sleep



# load wpscan vulnurable plugin database JSON
d = open('data/plugins.json').read()  #mebbie dl data file from github or use wpscan api...>http://stackoverflow.com/questions/5318747/using-python-to-extract-dictionary-keys-within-a-list
data = json.loads(d)

# define dict of random user agents , also in the future use the wpscan supplied list ;)
user_agents = [ 
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
    'Opera/9.25 (Windows NT 5.1; U; en)',
    'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
    'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
    'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.12) Gecko/20070731 Ubuntu/dapper-security Firefox/1.5.0.12',
    'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
    'Mozilla/5.0 (Windows NT 5.2; RW; rv:7.0a1)   Gecko/20091211 SeaMonkey/9.23a1pre',
    'Mozilla/5.0 (X11; U; Linux i686; ru; rv:33.2.3.12) Gecko/20120201 SeaMonkey/8.2.8',
    'Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20120501 Firefox/12.0 SeaMonkey/2.9.1 Lightning/1.4',
    'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.0 Safari/532.5',
	'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/9.0.601.0 Safari/534.14',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1',
	'Mozilla/5.0 (Windows; U; Windows NT 5.1; tr; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8 ( .NET CLR 3.5.30729; .NET4.0E)',
	'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1',
	'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:7.0.1) Gecko/20100101 Firefox/7.0.1',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6',
	'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1',
	'Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120403211507 Firefox/12.0',
	'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1',
	'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
	'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0)',
	'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
	'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5'
]

#define target server host
host = str(sys.argv[1])

#define delay on requests
minpause = int(sys.argv[2])
maxpause = int(sys.argv[3])

i=0 #set counter for progress bar
#count number of popular plugins (for use in porgressbar...)
count = 0
for plugin, popval in data.items():
    if popval['popular'] == 1: #or pop['popular'] == 0: 
    	count = count+1


# for each vulnurable plugin check if folder/readme exists
# only check for popular plugins;saves time, add the 'or' section in the comment to check for all plugins
for plugin, popval in data.items():
    if popval['popular'] == 1: #or pop['popular'] == 0: 
  
		version = choice(user_agents) #pick random user agents from user agents dict
		url = "/wp-content/plugins/"+plugin+"/readme.txt"

		probe = httplib.HTTP(host)
		# write your headers
		probe.putrequest("GET", url)
		probe.putheader("Host", host)
		probe.putheader("User-Agent", version)
		probe.putheader("Content-type", "text/html; charset=\"UTF-8\"")
		probe.endheaders()

		# get the response
		statuscode, statusmessage, header = probe.getreply()
		if statuscode == 200:
			print " found: " + url
		# else: # debug
		# 	print "not found: " + url # debug
		sleep(randint(minpause,maxpause)) # pause for random interval between 10 and 100 seconds between probes/requests
		i = i+1
		#prog = math.floor((float(i) / float(len(data)) )*100) # uncomment when scanning all plugins
		prog = math.floor((float(i) / float(count) )*100) #comment when scanning all plugins
		sys.stdout.write('\r')
		sys.stdout.write("[%-20s] %d%%" % ('='*int(prog), int(prog)))
		sys.stdout.flush()


