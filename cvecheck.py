#!/usr/bin/env python3

"""
COMING SOON
	-Also date of modification
	-Also output reference links about CVEs
"""

from sys import exit
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse, urlencode, quote
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from json import loads
import argparse

today = datetime.now() #.strftime('%Y-%m-%d')

# Arguments parsing
parser = argparse.ArgumentParser()
parser.add_argument('-d', default=today, dest='DATE', help = 'Specify the date range in which you want to find CVEs.')
parser.add_argument('-s', default=1000, dest='SIZE', help = 'Specify the maximum number of CVEs to look into (Up to 5000 due to NIST security.)')
parser.add_argument('-cvss', default=8.5, dest='CVSS', help='Specify the minimun cvss3 score you want to look for.')
parser.add_argument('-t', default='', dest='TGTOKENID', nargs=2)
namespace = parser.parse_args()


#set of telegram tokens
try:
	tgtoken = namespace.TGTOKENID[0]
	tgid = namespace.TGTOKENID[1]
except(IndexError):
	tgtoken = ''
	tgid = ''

#set of query params
cvss = float(namespace.CVSS)
size = namespace.SIZE
date = namespace.DATE
submonth = timedelta(weeks=4)
endate = date.strftime('%Y-%m-%d')
stdate = (date - submonth).strftime('%Y-%m-%d')


query = '?resultsPerPage=' +  str(size) + '&pubStartDate=' + quote(stdate) + quote('T00:00:00:000 UTC-05:00') + '&pubEndDate=' + quote(endate) + quote('T00:00:00:000 UTC-05:00')

print('\n')
print('Searching for critical CVEs between: ', stdate, ' and ', endate, '\n')
print('...\n')


cves = []


tgurl = 'https://api.telegram.org/bot'
tgfull = '{0}{1}/sendMessage'.format(tgurl, tgtoken)
feedlink = 'https://services.nvd.nist.gov/rest/json/cves/1.0' + query

#print('\n Quering feedlink: ' + feedlink + '\n \n ')


#get the last 20 modified CVEs
getjson = urlopen(Request(feedlink, headers={'User-Agent': 'Mozilla'}))
jsonr = loads(getjson.read().decode('utf-8'))
n = jsonr['totalResults']

print('... retring CVEs ... \n')
print('... found ', n, 'CVEs  ...\n')
print('... parsing', len(jsonr['result']['CVE_Items']), ' of them ...\n\n')

for i in range(0,n):
	try:
		cve = jsonr['result']['CVE_Items'][i]
		score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
		name = cve['cve']['CVE_data_meta']['ID']
		info = cve['cve']['description']['description_data'][0]['value']
		if score >= cvss:
			result = '{0} {1} ({2}...)' \
				.format(name, score, info[0:50])
			cves.append(result)
			print(result)
	except(ValueError, KeyError, TypeError, IndexError):
		continue


#data for telegram bot
tgdata = '{0} report: \n {1}' .format(date, '\n'.join(cves))
tgparams = urlencode({'chat_id': tgid, 'text': tgdata}).encode('utf-8')

print('\nDONE!\n')

if len (cves) == 0:
	print('No critical vulns found for today. Let\'s get into other thing, butterfly.')
	exit(0)
else:
	#print('\n'.join(cves))
	print('\n\n ', len(cves), ' critical CVEs found. \n')
	if tgtoken == '' or tgid == '':
		print('\nTelegram thing not working yet. But it will. Sorry friend.')
		exit(1)
	else:
		try:
			urlopen(tgfull, tgparams)
			print('Telegram alert sent')
			exit(2)

		except:
			print('Telegram alert did not sent, check your token and ID')
			exit(3)
