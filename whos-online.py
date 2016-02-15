#!/usr/bin/python
# V1

import urllib
import openpyxl
import nmap
import yaml
import os
import sys

scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
nm = nmap.PortScanner()


def load_config(workbook):
	with open(os.path.join(scriptdir, workbook),  'r') as config_file:
		return yaml.load(config_file)

def update_db(db_url): # Rename function to downloading database
	if db_url == 'offlinedb':
		print 'Offline DB, can\'t update.'
		pass
	else:
		urllib.urlretrieve (db_url, "data/mac_database.xlsx")
		print 'Database Updated.'

def whos_online():
	network_data = scan_network()
	return list_found_macs(network_data)

def scan_network(): # Function arguments for the scan ip and netmask bits maybe options
	print 'Starting Scan.'
	scan_data = nm.scan((config_data['DEFAULT_GATEWAY'] + '/' + str(config_data['NETMASK_BITS'])), arguments='-sP')
	print 'Scan duration', scan_data['nmap']['scanstats']['elapsed'], 'seconds.'
	return nm # do i need to return nm? 

def list_found_macs(data): # changed to data from argument instead of global 'nm'
	found_macs = []
	for host in data.all_hosts():
		if 'mac' in data[host]['addresses']:
			found_macs.append(data[host]['addresses']['mac'])
			print host, data[host]['vendor']
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
	online = {}
	if found_macs != None:
		for macs in known_devices:
			for mac in found_macs:
				nick = macs[1]
				if mac == macs[2]:
					if online.get(nick, 'none') == 'none':
						online[nick] = 1
					else:
						online[nick] = online[nick] + 1
		return online
	else:
		print 'error no MACs found online.'

config_data = load_config('data/config.yml')
update_db(config_data['DATABASE_URL'])
whos_online = whos_online()
ws = load_worksheet('data/mac_database.xlsx')
known_devices = parse_db(ws)
online = check_whos_online(known_devices, whos_online)
print online


 
