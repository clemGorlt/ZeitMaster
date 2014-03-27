import argparse
from datetime import datetime, timedelta
import sys
import locale

class tuple(object):
	def __init__(self,numb,deriv):
		self.number=numb
		self.derivation=deriv

def strToDate(arg,fmt):
	locale.getdefaultlocale()
	try:
		arg=datetime.strptime(arg,fmt)
	except ValueError as e:
		if len(e.args)>0 and e.args[0].startswith('unconverted data remains:'):
			arg= arg[:-(len(e.args[0])-26)]
			arg= datetime.strptime(arg,fmt)
		else:
			raise e
	return arg

def printArray(array):
	print('Array of derivation: ')
	for d in array:
		print(d.number,"|",d.derivation)

def processArray(array):
	print('processing the array...')

	minDiff=timedelta(days=2)#suppose to be max possible delta
	maxDiff=timedelta(microseconds=0)
	avgDiff=timedelta(microseconds=0)
	for d in array:
		if d.derivation>maxDiff:
			maxDiff=d.derivation
		if d.derivation<minDiff:
			minDiff=d.derivation
		avgDiff+=d.derivation

	avgDiff/=len(array)
	print('finished')
	print(minDiff,'<',avgDiff,'<',maxDiff)

fmt='%b %d, %Y %H:%M:%S.%f'
fmt_HTTP='%a, %d %b %Y %H:%M:%S %Z'#example: Sun, 16 Sep 2012 12:50:01 GMT
derivArray=[]
argParser = argparse.ArgumentParser(description='Zeitmaster: pcap time Analyser')
argParser.add_argument('-f',action='append', help='Filename')
args = argParser.parse_args()
if args.f is not None:
	filename = args.f
	i=0
	debut=0
	fin=0
	for line in sys.stdin:
		print("BEGIN\n processing data from pcap")
		print(line)
		#frame.time/ip.proto/udp.port/tcp.port/http.response->1 true|0 false/http.date/frame.number
		tab=line.split("\\")
		#print(tab[1])
		if i==1:
			debut=tab[0]
		#example for the next ntp-search
		if tab[2]=='68,67\n': # this line is DHCP
			print("DHCP")
		
		if '80' in tab[3] or '443' in tab[3]: # let's say http can only use tcp
			print("HTTP")
			print(repr(tab[4]))
			if tab[4]=='1':
				frame=strToDate(tab[0],fmt)
				http=strToDate(tab[5],fmt_HTTP)
				d=tuple(tab[6].rstrip('\n'),(frame-http))
				derivArray.append(d)
		i=i+1
		fin=tab[0]
		print("finished processing data from pcap")
	print(" debut/fin: ",debut,"/",fin)
	#print(repr(fin))
	debut=strToDate(debut,fmt)
	fin=strToDate(fin,fmt)
	print("delta:",(fin-debut))
	
	processArray(derivArray)
	printArray(derivArray)	
		
else:
	print("file not found ")
