import argparse
from datetime import datetime, timedelta
import sys
import locale


class tuple():
    def __init__(self, x, avg, z):
        self.minDiff = x
        self.avgDiff = avg
        self.maxDiff = z

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
def processLists(http,ntp):
	h=0
	n=0
	if not http:
		print("there were no HTTP-response packet")
	else:
		h=1
		http=processList(http)
	if not ntp:
		print("there were no NTP packet")
	else:
		n=1
		ntp=processList(ntp)
	if h==0 and n==0:
		print("there were neither http-response nor ntp packet to  analyse")
		exit(0)
	else:
		if h==1:
			print("average time derivation from http-response: ")
			print((http.avgDiff.seconds%3600),"sec with min",(http.minDiff.seconds%3600)," and max", (http.maxDiff.seconds%3600))
		if n==1:
			print("average time derivation from ntp-response: ")
			print((ntp.avgDiff.seconds%3600),"sec with min",(ntp.minDiff.seconds%3600)," and max", (ntp.maxDiff.seconds%3600))

def processList(array, bound=24):
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
	#print('Min < Average < Max:')
	#print(minDiff,'<',avgDiff,'<',maxDiff)
	#avgDiff=avgDiff.seconds%3600 #hours are due to the different Timezone, this is not what we are looking for
	return tuple(minDiff,avgDiff,maxDiff)

def printList(list):
	for elt in list:
		print(elt)

fmt='%b %d, %Y %H:%M:%S.%f'
fmt_HTTP='%a, %d %b %Y %H:%M:%S %Z'#example: Sun, 16 Sep 2012 12:50:01 GMT
fmt_NTP='%b %d, %Y %H:%M:%S.%f'#example: Jan  1, 1970 01:00:00.000000000
derivList=[]
ntpList=[]
cptList=0
cptNTP=0
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
		#frame.time/ip.proto/udp.port/tcp.port/http.response->1 true|0 false/http.date/ntp.rec/ntp.flags.mode->Client3|Server4/frame.number
		tab=line.split("\\")
		if i==1:
			debut=tab[0]
		if '123' in tab[2]: #udp.port
			if '4' in tab[7]:#4 means server response
				frame=strToDate(tab[0],fmt)
				ntp=strToDate(tab[6],fmt_NTP)
				ntpList.insert(cptNTP,(frame-ntp))
				cptNTP+=1
		if '80' in tab[3] or '443' in tab[3]: # let's say http can only use tcp
			if tab[4]=='1':#take only http response into account
				frame=strToDate(tab[0],fmt)
				http=strToDate(tab[5],fmt_HTTP)
				#d=tuple(tab[8].rstrip('\n'),(frame-http))
				derivList.insert(cptList,(frame-http))
				cptList+=1
		i+=1
		fin=tab[0]
	print("finished processing data from pcap")
	print("-->begin/end of the pcap: ",debut,"/",fin)
	debut=strToDate(debut,fmt)
	fin=strToDate(fin,fmt)
	print("-->delta:",(fin-debut))
	processLists(derivList,ntpList)
	#printArray(derivArray)	
		
else:
	print("file not found ")
