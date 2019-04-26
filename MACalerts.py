#!/usr/local/bin/python2.7
import os
import json
import subprocess
import datetime
import re
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
DBsave = "/root/names.txt" #File to save MAC,IP and resolved names to (does not contain as much as MAC because if a name is not provided, it does not add entry) 
MCsave = "/root/MAC.txt" #File to save MAC address's and IP's 
Error = "/root/error.txt"
email = "" #Add email to send alerts to here
path = "/var/log/dhcpd.log"
login = "" #Email to send alerts from (it can be the same)
password = "" #Password for sending email
def checkMAC(x):
	try:
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", x.lower()):
			return 1
	except:
		return 0
	else:
		return 0
def checkNAME(x):
	try:
		if re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", x):
			if re.findall('\(.*?\)',x):
				return 1
	except:
		return 0
	else:
		return 0
def checkIP(x):
	try:
		if re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", x):
			return 1
	except:
		return 0
	else:
		return 0
def sendemail(bbody, xmail, afrom, passz):
	toaddr = xmail 
	fromaddr = afrom
	msg = MIMEMultipart()
	msg['From'] = fromaddr
	msg['BCC'] = str(toaddr)
	msg['Subject'] = "New MAC Address Detected!"
	body = bbody
	msg.attach(MIMEText(body, 'html'))
	server = smtplib.SMTP('smtp.gmail.com', 587)
	server.starttls()
	server.login(fromaddr, passz)
	text = msg.as_string()
	server.sendmail(fromaddr, toaddr, text)
	server.quit() 
def Filter(data, zmail, zfnames, MACnames, passw, wogin, Berror):
	MACcount = 0
	count = 0
	newcount = 0
	namesunsorted =[]
	MACsunsorted = []
	with open(data) as mac:
		for lmac in mac:
			if checkNAME(lmac) == 1:
				if checkMAC(lmac.split(' ')[9].strip()) == 1:
					try:
						namesunsorted.append(lmac.split(' ')[7].strip() + " " + lmac.split(' ')[9].strip() + " " + lmac.split(' ')[10].strip())
					except:
						errorb = open(Berror, 'a+')
						errorb.write("Unable to parse dhcpd.log (lmac section). \nThis happens frequently, in most cases, it's nothing to worry about: " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n\n")
						errorb.close()
	with open(data) as cmac:
		for mmac in cmac:
			try:
				if checkMAC(mmac.split(' ')[9].strip()) == 1:
					if checkIP(mmac.split(' ')[7].strip()) == 1:
						try:
							MACsunsorted.append(mmac.split(' ')[7].strip() + " " + mmac.split(' ')[9].strip())
						except:
							errord = open(Berror, 'a+')
							errord.write("Unable to parse dhcpd.log (\"via\" part). \nThis happens frequently, in most cases, it's nothing to worry about: : " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n\n")
							errord.close()	
			except:
				errore = open(Berror, 'a+')
				errore.write("Unable to parse dhcpd.log (DHCPACK portion).\nThis happens frequently, in most cases, it's nothing to worry about: : " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n\n")
				errore.close()	
	### start DHCP name section: ###
	namesorted = []
	for line in namesunsorted:
		if line not in namesorted:
			namesorted.append(line)
	oldDevice = []
	with open(zfnames) as other:
		for zother in other:
			oldDevice.append(zother.strip())
	newDevice = []
	for line in namesorted:
		if not oldDevice:
			count += 1
			newDevice.append(line.strip())
		elif line.strip() not in oldDevice:
			count += 1
			newDevice.append(line.strip())
	###   end DHCP section   ###
	############################
	### start MAC/IP section ###
	MACsorted = []
	for line in MACsunsorted:
		if line not in MACsorted:
			MACsorted.append(line) #MACsorted = final MACs from log
	MACfilter = []
	with open(MACnames) as other:
		for zother in other:
			MACfilter.append(zother.strip()) #MACfilter = MACs from file
	MACfinal = []
	for line in MACsorted:
		if len(MACfilter) == 0:
#			print "MAC"
			MACcount += 1
			MACfinal.append(line.strip())
		elif line.strip() not in MACfilter:
			MACcount += 1
			MACfinal.append(line.strip())
	###########################
	if count == 0 and MACcount == 0:
		exit()
	elif count != 0 and MACcount != 0:
		aall = '<br>'.join(newDevice)
		ball = '<br>'.join(MACfinal)
		ddd = """Detected Names:\n %s <br><br>MAC Address/IPs:<br> %s""" % (aall, ball)
		try:
			sendemail(ddd, zmail, wogin, passw)
		except:
			errora = open(Berror, 'a+')
			errora.write("Unable to send email (count 2 section): " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n")
			errora.close()
		### write DHCP names to file ###
		for fileline in newDevice:
			file = open(zfnames, 'a+')
			file.write(fileline + "\n")
			file.close()
		### write MAC names to file ###
		for linefile in MACfinal:
			file = open(MACnames, 'a+')
			file.write(linefile + "\n")
			file.close()
	elif count != 0:
		all = '<br>'.join(newDevice)
		fll = """Detected Names:<br><br> %s""" % all
		try:
			sendemail(fll, zmail, wogin, passw)
		except:
			errora = open(Berror, 'a+')
			errora.write("Unable to send email (count): " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n")
			errora.close()
		### write DHCP names to file ###
		for fileline in newDevice:
			file = open(zfnames, 'a+')
			file.write(fileline + "\n")
			file.close()
	elif MACcount != 0:
		all = '<br>'.join(MACfinal)
		fll = """MAC Address/IPs:<br><br> %s""" % all
		try:
			sendemail(fll, zmail, wogin, passw)
		except:
			errora = open(Berror, 'a+')
			errora.write("Unable to send email (MAC): " + datetime.datetime.now().strftime("%I:%M:%S %p") + "\n")
			errora.close()
		#############################
		###	write MAC's to file   ###
		for linefile in MACfinal:
			file = open(MACnames, 'a+')
			file.write(linefile + "\n")
			file.close()
	else:
		exit()
if not os.path.exists(DBsave):
	with open(DBsave, 'w'): pass
if not os.path.exists(MCsave):
	with open(MCsave, 'w'): pass
Filter(path, email, DBsave, MCsave, password, login, Error)
