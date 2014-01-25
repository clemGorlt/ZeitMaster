import argparse

echo "BEGIN"
argParser = argparse.ArgumentParser(description='Zeitmaster: pcap time function')
argParser.add_argument('-f',action='append', help='Filename')
args = argParser.parse_args()
if args.f is not None:
	#filename = args.f
	
else:
	echo "file not found "
