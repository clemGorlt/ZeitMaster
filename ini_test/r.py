import argparse
from datetime import datetime, timedelta
import sys
import locale

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

def processList(array,bound=24):
	print('processing the list...')
	d=0
	minDiff=timedelta(days=2)#suppose to be max possible delta
	maxDiff=timedelta(microseconds=0)
	avgDiff=timedelta(microseconds=0)
	bounds=timedelta(hours=bound)
	skip=0
	for elt in array:
		if elt > bounds:
			skip+=1
			array.remove(elt)
			continue
		if elt >maxDiff:
			maxDiff=elt 
		if elt <minDiff:
			minDiff=elt
	avgDiff=sum(array,timedelta(0))/len(array)
	print('... finished: skiped ',skip,'element(s)')
	print('Min < Average < Max:')
	print(minDiff,'<',avgDiff,'<',maxDiff)
	avgDiff=avgDiff.seconds%3600 #hours are due to the different Timezone, this is not what we are looking for
	return avgDiff
fmt='%b %d, %Y %H:%M:%S.%f'
fmt_HTTP='%a, %d %b %Y %H:%M:%S %Z'#example: Sun, 16 Sep 2012 12:50:01 GMT
derivList=[]
cptList=0
argParser = argparse.ArgumentParser(description='Zeitmaster: pcap time Analyser')
argParser.add_argument('-f',action='append', help='Filename')
args = argParser.parse_args()
if args.f is not None:
	filename = args.f
	i=0
	debut=0
	fin=0
	print("BEGIN\n processing data from pcap")
	for line in sys.stdin:
		
		#print(line)
		#frame.time/ip.proto/udp.port/tcp.port/http.response->1 true|0 false/http.date/frame.number
		tab=line.split("\\")
		if i==1:
			debut=tab[0]
		#example for the next ntp-search
		#if tab[2]=='68,67\n': # this line is DHCP
			#print("DHCP")
		if '80' in tab[3] or '443' in tab[3]: # let's say http can only use tcp
			if tab[4]=='1':
				frame=strToDate(tab[0],fmt)
				http=strToDate(tab[5],fmt_HTTP)
				#d=tuple(tab[6].rstrip('\n'),(frame-http))
				derivList.insert(cptList,(frame-http))
				cptList+=1
		i+=1
		fin=tab[0]
	print("finished processing data from pcap")
	print(" debut/fin: ",debut,"/",fin)
	#print(repr(fin))
	debut=strToDate(debut,fmt)
	fin=strToDate(fin,fmt)
	print("delta:",(fin-debut))
	
	avg=processList(derivList)
	print("avg derivation:",avg,"sec(s)")
	#printArray(derivArray)	
		
else:
	print("file not found ")
