#!/usr/bin/python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from apscheduler.schedulers.background import BackgroundScheduler
import urlparse
import urllib
import openpyxl
import nmap
import yaml
import os
import time
import datetime
import sys

scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
nm = nmap.PortScanner()
scheduler = BackgroundScheduler()

def load_config(workbook):
	with open(os.path.join(scriptdir, workbook),  'r') as config_file:
		return yaml.load(config_file)

def download_db():
	if config_data['DATABASE_URL'] == 'offlinedb':
		print 'Offline DB, can\'t update.'
		pass
	else:
		urllib.urlretrieve (config_data['DATABASE_URL'], "data/mac_database.xlsx")
		print 'Database Updated.'

def whos_online():
	network_data = scan_network()
	return list_found_macs(network_data)

def scan_network():
	global scan_time
	print 'Starting Scan.'
	scan_data = nm.scan((config_data['DEFAULT_GATEWAY'] + '/' + str(config_data['NETMASK_BITS'])), arguments='-sP')
	scan_time = scan_data['nmap']['scanstats']['elapsed']
	print 'Scan duration', scan_time, 'seconds.'
	return nm

def list_found_macs(data): # changed to data from argument instead of global 'nm'
	found_macs = []
	for host in data.all_hosts():
		if 'mac' in data[host]['addresses']:
			found_macs.append(data[host]['addresses']['mac'])
			#print host, data[host]['vendor']
	return found_macs

def load_worksheet(workbook_filename):
	wb = openpyxl.load_workbook(filename = workbook_filename)
	return wb[config_data['DB_SHEET']]

def parse_db(ws):
	known_devices = []
	data_rows = []
	for row in ws.iter_rows(row_offset=1):
		data_rows.append(row)

	for data in data_rows:
		row_buffer = []
		for i in range(0,4):
			row_buffer.append(data[i].value)
		known_devices.append(row_buffer)
	return known_devices

def check_whos_online(known_devices, found_macs):
	online = {'info': {}, 'online': {}}
	if found_macs != None:
		for macs in known_devices:
			for mac in found_macs:
				nick = macs[1]
				if mac == macs[2]:
					if online['online'].get(nick, 'none') == 'none':
						online['online'][nick] = 1
					else:
						online['online'][nick] = online['online'][nick] + 1
		return online
	else:
		print 'error no MACs found online.'

def setup_schedulers(): # Change to config intervals
	scheduler.add_job(scan_whos_online,'interval',minutes=1)
	scheduler.add_job(download_db,'interval',minutes=30)

def print_time():
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	return st

def add_info():
	info = {}
	info['time'] = print_time()
	info['scan_time'] = scan_time
	return info

def scan_whos_online():
	global online
	print '\n',print_time()
	online_devices = whos_online()
	ws = load_worksheet('data/mac_database.xlsx')
	known_devices = parse_db(ws)
	online = check_whos_online(known_devices, online_devices)
	online['info'] = add_info()
	print online

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(online)
        return

    def log_request(self, code=None, size=None):
        print('Request')

    def log_message(self, format, *args):
        print('Message')

if __name__ == "__main__":
	config_data = load_config('config.yml')
	download_db()
	setup_schedulers()
	scheduler.start()
	scan_whos_online()
	try:
		server = HTTPServer(('', config_data['API_PORT']), MyHandler)
		print('Started http server')
		server.serve_forever()
	except KeyboardInterrupt:
		print('^C received, shutting down server')
		server.socket.close()
		




 
