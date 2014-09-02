from sys import argv
from datetime import datetime
"""
Creates a SQLite DB for IIS weblogs
"""

import os
import sqlite3

global cur

#Create database
def initDB():
	global db_conn
	global cur
	
	db_conn = sqlite3.connect('logs.db')
	db_conn.text_factory = str
	cur = db_conn.cursor()
	
	#IIS Log Table
	cur.execute('''CREATE TABLE IF NOT EXISTS IIS (
	timestamp DATETIME, 
	sitename TEXT, 
	serverip TEXT,
	method TEXT, 
	uri TEXT, 
	query TEXT,
	serverport INTEGER,
	username TEXT,
	clientip TEXT, 
	useragent TEXT, 
	status TEXT, 
	substatus TEXT, 
	win32status TEXT)''')
	
	return db_conn
	
def ingest(dir):
	#Loop directory
	for subdir, dirs, files in os.walk(dir):
		for f in files:		
			#Only look at regular logs for now
			if f.startswith('ex'): 
				#To hold records
				records = []
				
				#Open file for reading
				infile = os.path.join(subdir, f)
				input = open(infile, 'r')
				
				#Iterate over file
				for line in input.read().split('\n'):
					#Ignore comment lines
					if line.startswith("#"):
						continue
					
					#Create record
					record = line.split(' ')
					
					if len(record) < 5:
						continue
					
					#Fix timestamp
					record.reverse()
					date = record.pop()
					time = record.pop()
					timestamp = datetime.strptime(' '.join([date,time]), "%Y-%m-%d %H:%M:%S")
					record.append(timestamp)
					record.reverse()
					
					records.append(record)

				input.close()
				cur.executemany('''INSERT OR IGNORE INTO IIS VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', records)
				db_conn.commit()
					
if __name__ == "__main__":

	#Check usage
	if len(argv) != 2:
		print "Usage: python %s [path]" % argv[0]
		exit(1)
	
	cur = initDB().cursor()
	ingest(argv[1])
	