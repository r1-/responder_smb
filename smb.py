#!/usr/bin/env python

##################################################################################################################
###################################    Importing Libraries   #####################################################
##################################################################################################################

import socket
from time import time
from struct import pack, unpack
from random import getrandbits
from binascii import hexlify
from subprocess import check_output
from sys import platform, argv
from glob import glob
from  multiprocessing import Process
import logging
import os
from optparse import OptionParser

##################################################################################################################
##########################################    Global  Variables    ###############################################
##################################################################################################################

glob_MaxBufferSize = 4356
glob_uid=100
glob_natOS__ = "SMB RESPONDER Version 1"
glob_natLAN__ = "SMB Responder vers 1.0"
glob_tid=1
glob_Files = {}
glob_FID = 13373
glob_tid_IPC = 0
glob_curdir = '.'
glob_inter = False
logger = logging.getLogger('SMBResponder')

IPC = '\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00'

#TRANS MSG && LEVEL INFO
SMB_QUERY_FS_ATTRIBUTE_INFO = b'\x05\x01'
SMB_QUERY_FS_VOLUME_INFO = b'\x02\x01'
SMB_TRANS2_FIND2 = b'\x01\x00'
SMB_TRANS2_QUERYFILE = b'\x06\x00'
SMB_TRANS2_DFSREF = b'\x10\x00'
SMB_TRANS2_QUERYPATH = b'\x05\x00'
SMB_TRANS2_QUERYFS = b'\x03\x00'
SMB_TRANS2_QUERYFILEINFO = b'\x07\x00'
SMB_TRANS_NETSHAREINFO = b'\x10\x00'
SMB_LEVEL_INFO_BASIC = b'\xec\x03'
SMB_LEVEL_INFO_STANDARD = b'\xed\x03'
SMB_LEVEL_INTERNAL_INFO = b'\xee\x03'
SMB_LEVEL_ALL_INFO = b'\x07\x01'
SMB_LEVEL_FIND_INF0_BOTH = b'\x04\x01'
SMB_LEVEL_FIND_INF0_FULL = b'\x02\x01'
SMB_LEVEL_FILE_BASIC_INFO = b'\x01\x01'
SMB_LEVEL_INTERNAL_INFO = b'\xee\x03'
SMB_LEVEL_FILE_STREAM_INFO = b'\xfe\x03'
SMB_LEVEL_EA_INFO = b'\xef\x03'

# NTLM 
NTLM_NEGOTIATE = b'\x01\x00\x00\x00'
NTLM_AUTH = b'\x03\x00\x00\x00'

# NAMED PIPE
WAIT_NAMED_PIPE = b'\x53\x00'

# Error codes
STATUS_SUCCESS = '\x00\x00\x00\x00'
STATUS_MORE_PROCESSING_REQUIRED = '\x16\x00\x00\xc0'
STATUS_OBJECT_NAME_NOT_FOUND = '\x34\x00\x00\xc0'
STATUS_INVALID_HANDLE = '\x08\x00\x00\xc0'
STATUS_NOT_SUPPORTED = '\xbb\x00\x00\xc0'
STATUS_NOT_FOUND = '\x25\x02\x00\xc0'
STATUS_NOT_IMPLEMENTED = '\x02\x00\x00\xc0'
STATUS_NO_SUCH_FILE = '\x0f\x00\x00\xc0'
STATUS_OBJECT_PATH_NOT_FOUND = '\x3a\x00\x00\xc0'
STATUS_FILE_IS_A_DIRECTORY = '\xba\x00\x00\xc0'
STATUS_UNSUCCESSFUL = '\x01\x00\x00\xc0'
STATUS_END_OF_FILE = '\x11\x00\x00\xc0'
STATUS_INVALID_PARAMETER = '\x0d\x00\x00\xc0'
STATUS_REQUEST_NOT_ACCEPTED = '\xd0\x00\x00\xc0'

##################################################################################################################
########################################      Global Function Definition    ######################################
##################################################################################################################

def string(arg1, arg2=None):
	try:
		return str(arg1, arg2)		
	except TypeError:
		return str(arg1)

def bytes2(arg1, arg2=None):
	try:
		return bytes(arg1, arg2)
	except TypeError:
		return bytes(arg1)

def byte2print(bytestr):
	return 'b\'' + ''.join( [ "\\x%02X" % ord( x ) for x in string(bytestr, "ISO-8859-1")] ).strip() + '\''

def SMBSize(buffer):
	return unpack(">I", buffer[0:4])[0]

#Calculate total SMB packet len.
def longueur(payload):
	length = pack(">i", len(''.join(payload)))
	return length

#Set MID SMB Header field.
def midcalc(data):
	pack=data[30:32]
	logger.info("mid : %s (%i)" % (byte2print(pack) , unpack('H', pack)[0]))
	return pack

#Set UID SMB Header field.
def uidcalc(data):
	pack=data[28:30]
	return pack

#Set PID SMB Header field.
def pidcalc(data):
	pack=data[26:28]
	return pack

#Set TID SMB Header field.
def tidcalc(data):
	pack=data[24:26]
	logger.info("Tid : %s (%i)" % (byte2print(pack), unpack('H', pack)[0]))
	return string(pack, "ISO-8859-1")

def getBCC(data):
	pack=data[41:43]
	pack=unpack("<H", pack)
	logger.info("Bcc : %i" % pack)
	return pack[0]

def getService(data):
	size = getBCC(data) - 7
	pack=data[44:44+size]
	logger.info("Service : (%s) %s" % (bytesTostring(pack), byte2print(pack)))
	return pack

def getShare(data):
	service = string(getService(data), "ISO-8859-1")
	share = service.split('\\')[-1]
	return share

def bytesTostring(data_in):
	data_out = string(data_in, "ISO-8859-1").replace("\x00", "")
	return data_out

def strTobytes2(data_in):
	data_out = ''
	for letter in data_in:
		data_out+= letter + '\x00'
	return data_out + '\x00\x00', 

def getNameFile(data):
	pack=data[84:]
	filename = bytesTostring(pack)
	logger.info("Filename : %s" % filename)
	return filename

#Function to get Server Time
def server_time_f():
	unix_time=11644473600*10000000
	curr_t=time()*10000000+unix_time
	hex_curr_t=hex(int(curr_t))
	stra=string(hex_curr_t)
	timelow=stra[0:(len(stra)-8)]
	timehigh=stra[(len(stra)-8):len(stra)]
	timehigh='0x'+timehigh
	st=(pack('<II',int(timehigh,16),int(timelow,16)))
	return st;

#Function convert system time
def time_funct(stime):
	unix_time=11644473600*10000000
	curr_t=stime*10000000+unix_time
	hex_curr_t=hex(int(curr_t))
	stra=string(hex_curr_t)
	timelow=stra[0:(len(stra)-8)]
	timehigh=stra[(len(stra)-8):len(stra)]
	timehigh='0x'+timehigh
	st=(pack('<II',int(timehigh,16),int(timelow,16)))
	return st;

def file_to_hex(filename):
	with open(filename, 'rb') as f:
		content = f.read()
		bin_file=hexlify(content)
	return bin_file

def getBlobLength(data):
	BlobLength=data[47:49]
	return unpack('H', BlobLength)[0]

def findNTLMSSP(data):
	logger.info("Size : %i" % getBlobLength(data) )
	buffer=string(data[59:59+getBlobLength(data)], "ISO-8859-1")
	logger.debug("buffer ntlmssp : %s" % buffer )
	pos=buffer.find("NTLMSSP")	
	if pos == -1:
		return 0
	messageType=data[59+pos+8:59+pos+12]
	logger.info("message type : %s (%s)" % (byte2print(messageType), hex(unpack('I',messageType)[0])) )
	return [pos, messageType]

def getSubCmd(data):
	subCommand=data[61:63]
	logger.info("SubCommand : %s (%s)" % (byte2print(subCommand), hex(unpack('H',(subCommand))[0]) ))
	return subCommand

def getLevelInfo(data):
	level=data[68:70]
	return level

def getLevelFileInfo(data):
	level=data[70:72]
	return level

def getLevelFindInfo(data):
	level=data[74:76]
	return level

def getFID(data):
	FID=data[37:39]
	return FID

def reterror(error):
	return error, b'\x00\x00\x00', 3

##################################################################################################################
####################### Analyse Packet - Dialect Negotiation Class - verify SMB protocol version #################
##################################################################################################################

class Negotiate_Request:
	def __init__(self, buffer1):
		paquet=buffer1
         
		if paquet[0:4] == b'\xffSMB' :

          # Negotiation of dialects 
          ## SMB Received Packet Cmd Analyser 
			logger.info("command : %s" % paquet[9] )
			if paquet[4]==0x72 and (paquet[9] & 0x80) ==0:  
				logger.info("**Negotiate Protocol Request" )
                                ## Detection du dialect
				dialect = buffer1[36:-1].split(b'\x00\x02')
				logger.info("dialect : %s" % dialect )
				if b'NT LM 0.12' in dialect:
					self.dialect = (dialect.index(b'NT LM 0.12'))
				elif b'NT LANMAN 1.0' in dialect:
					self.dialect = (dialect.index(b'NT LANMAN 1.0'))
				elif b'PC NETWORK PROGRAM 1.0' in dialect:
					self.dialect = (dialect.index(b'PC NETWORK PROGRAM 1.0'))
				elif b'PCLAN1.0' in dialect:
					self.dialect = (dialect.index(b'PCLAN1.0'))
				elif b'MICROSOFT NETWORKS 1.03' in dialect:
					self.dialect = (dialect.index(b'MICROSOFT NETWORKS 1.03'))
				elif b'MICROSOFT NETWORKS 3.0' in dialect:
					self.dialect = (dialect.index(b'MICROSOFT NETWORKS 3.0'))
				elif b'LANMAN1.0' in dialect:
					self.dialect = (dialect.index(b'LANMAN1.0'))
				elif b'LM1.2X002' in dialect:
					self.dialect = (dialect.index(b'LM1.2X002'))
				elif b'LANMAN2.1' in dialect:
					self.dialect = (dialect.index(b'LANMAN2.1'))
				elif b'Samba' in dialect:
					self.dialect = (dialect.index(b'Samba'))
				elif b'CIFS' in dialect:
					self.dialect = (dialect.index(b'CIFS'))
				else :  
					logger.error("**Protocol error : No Dialect Compatibility")
					self.status = STATUS_NOT_SUPPORTED
					exit() # fixed
				logger.info("Position of dialect : %i (%s)" % (self.dialect, dialect[self.dialect]) )

			else :
				logger.error("**Protocol error")
				self.status = STATUS_INVALID_PARAMETER
				exit() #fixed
		else: # SMB 2 ??
			logger.error("**Protocol not supported")
			self.status =  STATUS_NOT_SUPPORTED
			exit() #fixed

		self.Wordcount = buffer1[0]
		self.count = unpack("H", buffer1[1:3])[0]
		if self.count < 2:
			logger.error("**Protocol Negotiate issue")
         
	def GetDialect(self):
		return self.dialect
      
##################################################################################################################
###################################   NetBios Class    ###########################################################
##################################################################################################################

class NetBios():
	fields = dict([
		("MsgType", "\x00"),
		("SMBPacketLen", "\x00\x00\x00"),
	])

	def create_p_NetBios(self, header_size, body_size):
		self.fields["SMBPacketLen"] = pack(">i", header_size + body_size)
		self.fields["SMBPacketLen"] = string(self.fields["SMBPacketLen"], "ISO-8859-1") [1:4]
		packetNetBios_str = self.fields["MsgType"] + self.fields["SMBPacketLen"]
		packetNetBios_bytes=bytes2((packetNetBios_str), "ISO-8859-1")
		return packetNetBios_bytes

##################################################################################################################
###################################    SMB Header Packet Response Class    #######################################
##################################################################################################################

class SMBHeader():
	fields = dict([
		("Protocol", "\xffSMB"),
		("Command", ""),
		("Status", "\x00\x00\x00\x00" ),
		("Flags", "\x88"),
		("Flags2", "\x43\xc8"),
		("Pidhigh", "\x00\x00"),
		("Signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("Reserved", "\x00\x00"),
		("Tid", "\x00\x00"),
		("Pid", ""),
		("Uid", "\x00\x00"),
		("Mid", ""),
	])

	def create_p_header(self, h_type):

		self.fields["Command"] = pack('B', h_type)

		packetHeader_str = self.fields["Protocol"] + string(self.fields["Command"], "ISO-8859-1") + self.fields["Status"] + \
			 self.fields["Flags"] + self.fields["Flags2"] + self.fields["Pidhigh"] + \
			 self.fields["Signature"] + self.fields["Reserved"] + self.fields["Tid"] + \
			 string(self.fields["Pid"], "ISO-8859-1") + self.fields["Uid"] + string(self.fields["Mid"], "ISO-8859-1")
		packetHeader_bytes=bytes2((packetHeader_str), "ISO-8859-1")
		return packetHeader_bytes, len(packetHeader_str)

	def setErrorCode(self, errorcode):
		self.fields["Status"]=errorcode
	def setmid(self, mid):
		self.fields["Mid"]=mid
	def settid(self, tid):
		self.fields["Tid"]=tid
	def setflags2(self, flags):
		self.fields["Flags2"]=flags
	def setpid(self, pid):
		self.fields["Pid"]=pid
	def setuid(self, uid):
		self.fields["Uid"]=uid
		
				
##################################################################################################################
###################################    Negotiate Packet Response Class (for dialect) #############################
##################################################################################################################
    
class SMBNegoAns():
    ## Some field are not used because now we dont need Security
	fields_SMB_parameter = dict([
		("Wordcount",    ""),
		("Dialect",      ""),
		("Securitymode", "\x03"),
		("MaxMpx",       "\x0a\x00"),
		("MaxVc",        "\x01\x00"),
		("Maxbuffsize",  "\x04\x11\x00\x00"),
		("Maxrawbuff",   "\x00\x00\x01\x00"),
		("Sessionkey",   "\x00\x00\x00\x00"),
		("Capabilities", "\xfc\xf3\x01\x80"),
		("Systemtime",   ""),
		("Srvtimezone",  "\x88\xff"),
		("Keylength",    "\x00"),
	])

	fields_SMB_data = dict([
		("ByteCount",	   "\x3a\x00"),
		("GUID",		   "\xde\xad\xbe\xef\xde\xad\xbe\xef"\
							"\xde\xad\xbe\xef\xde\xad\xbe\xef"),
		("SecurityBlob",  "\x60\x28\x06\x06\x2b\x06\x01" \
								"\x05\x05\x02\xa0\x1e\x30\x1c" \
								"\xa0\x1a\x30\x18\x06\x0a\x2b" \
								"\x06\x01\x04\x01\x82\x37\x02" \
								"\x02\x1e\x06\x0a\x2b\x06\x01" \
								"\x04\x01\x82\x37\x02\x02\x0a"),
	])

	def __init__(self, paquet):
		a=Negotiate_Request(paquet)
		self.dialect = a.GetDialect()
	
	def calculate(self):

        ##Pack Max Buffer Size
		self.fields_SMB_parameter["Maxbuffsize"] = pack("<i",glob_MaxBufferSize)
        
        ##Calculate Server Time...
		self.fields_SMB_parameter["Systemtime"] = string(server_time_f(),"ISO-8859-1")
		self.fields_SMB_parameter["Maxbuffsize"] = string(self.fields_SMB_parameter["Maxbuffsize"], "ISO-8859-1")

        ##Set Dialect
		self.fields_SMB_parameter["Dialect"] = string(self.dialect)
		self.fields_SMB_parameter["Dialect"] = pack("<H", self.dialect)
        
	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()

		self.fields_SMB_parameter["Dialect"] =string(self.fields_SMB_parameter["Dialect"], "ISO-8859-1") 
		SMB_Param_str = self.fields_SMB_parameter["Dialect"] \
		  + self.fields_SMB_parameter["Securitymode"] + self.fields_SMB_parameter["MaxMpx"] \
		  + self.fields_SMB_parameter["MaxVc"] + self.fields_SMB_parameter["Maxbuffsize"] \
		  + self.fields_SMB_parameter["Maxrawbuff"] + self.fields_SMB_parameter["Sessionkey"] \
		  + self.fields_SMB_parameter["Capabilities"] + self.fields_SMB_parameter["Systemtime"] \
		  + self.fields_SMB_parameter["Srvtimezone"] + self.fields_SMB_parameter["Keylength"]
        
		self.fields_SMB_parameter["Wordcount"] = pack("<B",int(len(SMB_Param_str)/2))
		self.fields_SMB_parameter["Wordcount"] = string(self.fields_SMB_parameter["Wordcount"], "ISO-8859-1")
		SMB_Data_str = self.fields_SMB_data["ByteCount"] + self.fields_SMB_data["GUID"] + \
							self.fields_SMB_data["SecurityBlob"]

		packetBody_str = self.fields_SMB_parameter["Wordcount"] + SMB_Param_str + SMB_Data_str

		packetBody_bytes=bytes2((packetBody_str), "ISO-8859-1")
		return status, packetBody_bytes, len(packetBody_str)
						  
##################################################################################################################
###################################    Session Setup AndX Class : ntlmssp exchanges ##############################
##################################################################################################################
    
class SessSetupAndXAns:
    ## Some field are not used because now we dont need Security
	fields_SMB_parameter = dict([
		("Wordcount",             "\x04"),
		("AndXCommand",           "\xff"),
		("Reserved",              "\x00"),
		("Andxoffset",            "\x00\x00"),
		("Action",                "\x00\x00"),
		("SecBlobLen",            "\x00\x00"),
	])

	fields_SMB_data = dict([
		("Bcc" ,                   "\x89\x01"),
		("SecurityBlob",				"\xa1\x81\xa4\x30\x81\xa1\xa0\x03\x0a" \
											"\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01" \
											"\x04\x01\x82\x37\x02\x02\x0a\xa2\x81" \
											"\x8b\x04\x81\x88"),
			("NTLMIdentifier",			"\x4e\x54\x4c\x4d\x53\x53\x50\x00"),
			("NTLMChallenge",				"\x02\x00\x00\x00"),
			("TargetName",					"\x08\x00\x08\x00"),
			("OffsetName",					"\x38\x00\x00\x00"),
			("Flags",						"\x15\x82\x8a\x62"),
			("ServerChallenge",			""),
			("reserved",					"\x00\x00\x00\x00\x00\x00\x00\x00"),
			("TargetInfo",					"\x48\x00\x48\x00"),
			("OffsetInfo",					"\x40\x00\x00\x00"),
			("version",						"\x06\x01\xb0\x1d\x00\x00\x00\x0f"),
			("TargetNameStr",				"\x53\x00\x4d\x00\x42\x00\x72\x00"),
			("TargetInfoStr",				"\x02\x00\x08\x00\x53\x00\x4d\x00\x42\x00\x72\x00" + \
												"\x01\x00\x08\x00\x53\x00\x4d\x00\x42\x00\x72\x00" + \
												"\x04\x00\x08\x00\x53\x00\x4d\x00\x42\x00\x72\x00" + \
												"\x03\x00\x08\x00\x53\x00\x4d\x00\x42\x00\x72\x00" + \
												"\x06\x00\x04\x00\x01\x00\x00\x00" + \
												"\x07\x00\x08\x00"),
		("NativeOs" , "Given in a Global Variable glob_natOS__"),                           
		("NativeOsTerminator" , "\x00\x00"),
		("NativeLAN" , "Given in a Global Variable glob_natLAN__"),
		("NativeLANTerminator" , "\x00\x00"),    
	])
	fields_SMB_data_auth = dict([
		("Bcc" ,                   "\x89\x01"),
		("SecurityBlob",           "\xa1\x07\x30\x05\xa0\x03\x0a\x01"),
			("negresult",					"\x00"),
		("NativeOs" , "Given in a Global Variable glob_natOS__"),                           
		("NativeOsTerminator" , "\x00\x00"),
		("NativeLAN" , "Given in a Global Variable glob_natLAN__"),
		("NativeLANTerminator" , "\x00\x00"),    
	])
		
		
	def __init__(self, paquet):
		self.NTLMSSP = findNTLMSSP(paquet)
		self.status = STATUS_SUCCESS
		if self.NTLMSSP[1] == NTLM_AUTH:
			logger.info("Session setup andX request NTLMSSP AUTH")
			NTLMSSP_auth(paquet[self.NTLMSSP[0]:])
		elif self.NTLMSSP[1] == NTLM_NEGOTIATE:
			logger.info("Session setup andX request NTLMSSP NEGOTIATE")
			NTLMSSP_Negotiate(paquet)
		else:	
			logger.error("**Authentication protocol not supported")
			self.status = STATUS_NOT_SUPPORTED
	
	def moreProcessing(self):
		if self.NTLMSSP[1] == NTLM_NEGOTIATE:
			return 1
		else:
			return 0
 
	def calculate(self):
		##Make Native OS and Native LAN compatible with standards when using unicode
		natOS_=''
		status = STATUS_SUCCESS

		for letter in glob_natOS__ :     
			letter=letter + '\x00'
			natOS_+=letter
		self.fields_SMB_data["NativeOs"]=natOS_
		self.fields_SMB_data_auth["NativeOs"]=natOS_
		natLAN_=''
		for letter in glob_natLAN__ :   
			letter=letter + '\x00'
			natLAN_+=letter
		self.fields_SMB_data["NativeLAN"]=natLAN_
		self.fields_SMB_data_auth["NativeLAN"]=natLAN_

		self.fields_SMB_data["TargetInfoStr"] = self.fields_SMB_data["TargetInfoStr"] \
									+ string(server_time_f(),"ISO-8859-1") + '\x00\x00\x00\x00'

		##Then calculate BCC
		#if self.ans=="nego":
		if self.NTLMSSP[1] == NTLM_NEGOTIATE:
			CompleteBCCLen =  self.fields_SMB_data["SecurityBlob"]+  \
									self.fields_SMB_data["NTLMIdentifier"]+  \
									self.fields_SMB_data["NTLMChallenge"]+  \
									self.fields_SMB_data["TargetName"]+  \
									self.fields_SMB_data["OffsetName"]+  \
									self.fields_SMB_data["Flags"]+  \
									self.fields_SMB_data["reserved"]+  \
									self.fields_SMB_data["TargetInfo"]+  \
									self.fields_SMB_data["OffsetInfo"]+  \
									self.fields_SMB_data["version"]+  \
									self.fields_SMB_data["TargetNameStr"]+  \
									self.fields_SMB_data["TargetInfoStr"]+  \
									self.fields_SMB_data["NativeOs"]+self.fields_SMB_data["NativeOsTerminator"] + \
									self.fields_SMB_data["NativeLAN"]+self.fields_SMB_data["NativeLANTerminator"] # +8 pour challenge
			self.fields_SMB_data["Bcc"] = pack("<H",len(CompleteBCCLen)+8)
			self.fields_SMB_data["Bcc"] = string(self.fields_SMB_data["Bcc"], "ISO-8859-1")
			status = STATUS_MORE_PROCESSING_REQUIRED
		#elif self.ans=="ok":
		elif self.NTLMSSP[1]==NTLM_AUTH:
			CompleteBCCLen =  self.fields_SMB_data_auth["SecurityBlob"]+  \
									self.fields_SMB_data_auth["negresult"]+ \
									self.fields_SMB_data_auth["NativeOs"]+self.fields_SMB_data_auth["NativeOsTerminator"] + \
									self.fields_SMB_data_auth["NativeLAN"]+self.fields_SMB_data_auth["NativeLANTerminator"]
			self.fields_SMB_data_auth["Bcc"] = pack("<H",len(CompleteBCCLen))
			self.fields_SMB_data_auth["Bcc"] = string(self.fields_SMB_data_auth["Bcc"], "ISO-8859-1")

		## Challenge
		challenge =  getrandbits(64)
		logger.info("challenge : %i" % challenge)
		self.fields_SMB_data["ServerChallenge"]  = pack("<Q", challenge)

		#if self.ans=="nego":
		if self.NTLMSSP[1] == NTLM_NEGOTIATE:
			##Security Blob Length Calculation
			self.fields_SMB_parameter["SecBlobLen"] = pack("<H",len(self.fields_SMB_data["SecurityBlob"]+\
				self.fields_SMB_data["NTLMIdentifier"] + self.fields_SMB_data["NTLMChallenge"] + \
				self.fields_SMB_data["TargetName"] + self.fields_SMB_data["OffsetName"] + \
				self.fields_SMB_data["Flags"] + self.fields_SMB_data["reserved"] + \
				self.fields_SMB_data["TargetInfo"] + self.fields_SMB_data["OffsetInfo"] +  self.fields_SMB_data["version"] + \
				self.fields_SMB_data["TargetNameStr"] + self.fields_SMB_data["TargetInfoStr"])+8)
			self.fields_SMB_parameter["SecBlobLen"] = string(self.fields_SMB_parameter["SecBlobLen"], "ISO-8859-1")
		#elif self.ans=="ok":
		elif self.NTLMSSP[1]==NTLM_AUTH:
			self.fields_SMB_parameter["SecBlobLen"] = '\x09\x00'
		return status

	def create_p_body(self):
		status = self.calculate()
		if self.status == STATUS_NOT_SUPPORTED:
			return reterror(self.status)

		SMB_Param_str = self.fields_SMB_parameter["AndXCommand"] \
							 + self.fields_SMB_parameter["Reserved"] + self.fields_SMB_parameter["Andxoffset"] \
							 + self.fields_SMB_parameter["Action"] + self.fields_SMB_parameter["SecBlobLen"]

		self.fields_SMB_parameter["Wordcount"] = pack("<B",int(len(SMB_Param_str)/2))
		self.fields_SMB_parameter["Wordcount"] = string(self.fields_SMB_parameter["Wordcount"], "ISO-8859-1")

		#if self.ans=="nego":
		if self.NTLMSSP[1] == NTLM_NEGOTIATE:
			SMB_Data_str = self.fields_SMB_data["Bcc"] + self.fields_SMB_data["SecurityBlob"] + \
								self.fields_SMB_data["NTLMIdentifier"] + self.fields_SMB_data["NTLMChallenge"] \
								+ self.fields_SMB_data["TargetName"] +  self.fields_SMB_data["OffsetName"] + \
								self.fields_SMB_data["Flags"] + string(self.fields_SMB_data["ServerChallenge"],"ISO-8859-1") \
								+ self.fields_SMB_data["reserved"] + self.fields_SMB_data["TargetInfo"] +\
								self.fields_SMB_data["OffsetInfo"] +  self.fields_SMB_data["version"] \
								+ self.fields_SMB_data["TargetNameStr"] + self.fields_SMB_data["TargetInfoStr"] \
								+ self.fields_SMB_data["NativeOs"] + self.fields_SMB_data["NativeOsTerminator"] \
								+ self.fields_SMB_data["NativeLAN"] + self.fields_SMB_data["NativeLANTerminator"]
		#elif self.ans=="ok":
		elif self.NTLMSSP[1]==NTLM_AUTH:
			SMB_Data_str = self.fields_SMB_data_auth["Bcc"] + self.fields_SMB_data_auth["SecurityBlob"] + \
							self.fields_SMB_data_auth["negresult"] + self.fields_SMB_data_auth["NativeOs"] \
							+ self.fields_SMB_data_auth["NativeOsTerminator"] + self.fields_SMB_data_auth["NativeLAN"] \
							+ self.fields_SMB_data_auth["NativeLANTerminator"]
			

		packetBody_str = self.fields_SMB_parameter["Wordcount"] + SMB_Param_str + SMB_Data_str

		packetBody_bytes=bytes2((packetBody_str), "ISO-8859-1")
		return status, packetBody_bytes, len(packetBody_str)


##################################################################################################################
###################################    Tree Connect Class : connect to a SMB tree  ###############################
##################################################################################################################
      
class SMBTreeConnAns():
    ## Some field are not used because now we dont need Security
	fields_SMB_parameter = dict([
		("Wordcount", "\x07"),
		("AndXCommand", "\xff"),
		("Reserved","\x00" ),
		("Andxoffset", "\x00\x00"),
		("OptionalSupport","\x01\x00"),
		("MaxShareAccessRight","\xff\x01\x00\x00"),
		("GuestShareAccessRight","\xff\x01\x00\x00"),
	])

	fields_SMB_data = dict([
		("Bcc", "\x94\x00"),
		("Service", "IPC"),
		("ServiceTerminator","\x00\x00\x00\x00"),      
	])

	#def __init__(self, service):
	def __init__(self, paquet):
		service=getShare(paquet)
		tid=tidcalc(paquet)
		if tid == '\x00\x00':
			global glob_tid
			glob_tid=glob_tid + 1
		if service==IPC: # "Named":
			self.fields_SMB_data["Service"] = "IPC"
			global glob_tid_IPC
			glob_tid_IPC = glob_tid

		else: #if service=="Share":
			self.fields_SMB_data["Service"] = "A:"	+ "\x00\x4e\x00\x54\x00\x46\x00\x53\x00\x00\x00"

	def calculate(self):
        
        #Complete Packet Len
		CompletePacket= string(self.fields_SMB_parameter["Wordcount"])+ string(self.fields_SMB_parameter["AndXCommand"])\
							+ string(self.fields_SMB_parameter["Reserved"]) +string(self.fields_SMB_parameter["Andxoffset"]) \
							+ string(self.fields_SMB_parameter["OptionalSupport"]) \
							+ string(self.fields_SMB_parameter["MaxShareAccessRight"]) \
							+ string(self.fields_SMB_parameter["GuestShareAccessRight"]) + string(self.fields_SMB_data["Bcc"])\
							 + string(self.fields_SMB_data["Service"]) + string(self.fields_SMB_data["ServiceTerminator"])

		## BCC Len Calc
		BccLen= (self.fields_SMB_data["Service"])+string(self.fields_SMB_data["ServiceTerminator"])
		self.fields_SMB_data["Bcc"] = pack("<H", len(BccLen))

		##Then reconvert..
		self.fields_SMB_data["Bcc"] = string(self.fields_SMB_data["Bcc"], "ISO-8859-1")
			  
	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()
		SMB_Param_str = self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["AndXCommand"] \
							 + self.fields_SMB_parameter["Reserved"] + self.fields_SMB_parameter["Andxoffset"] \
							 + self.fields_SMB_parameter["OptionalSupport"] + self.fields_SMB_parameter["MaxShareAccessRight"] \
							 + self.fields_SMB_parameter["GuestShareAccessRight"]

		SMB_Data_str = self.fields_SMB_data["Bcc"] + self.fields_SMB_data["Service"] + \
							self.fields_SMB_data["ServiceTerminator"]

		packetBody_str = SMB_Param_str + SMB_Data_str

		packetBody_bytes=bytes2((packetBody_str), "ISO-8859-1")
		return status, packetBody_bytes, len(packetBody_str)

##################################################################################################################
###################################    NTLM Negotiation classes  #################################################
##################################################################################################################

class NTLMSSP_Negotiate:
	def __init__(self, buffer):
		logger.debug("packet : %s" % byte2print(buffer))
		logger.debug("nego part : %s" % byte2print(buffer[59:]))
		blob=buffer[59:]
		oid=blob[4:10]
		SPN=blob[10:12]
		negtokenInit=blob[12:18]
		mechType=blob[18:30]
		NtlmsspIdentifier=blob[34:42]
		NTLMmessageType=blob[42:46]
		flags=blob[46:50]

		logger.info("oid : %s" % byte2print(oid))	
		logger.info("SPN : %s" % byte2print(SPN))
		logger.info("negtokenInit : %s" % byte2print(negtokenInit))
		logger.info("mechType : %s" % byte2print(mechType))
		logger.info("NTLM Identifier : %s" % byte2print(NtlmsspIdentifier))	
		logger.info("NTLM message : %s" % byte2print(NTLMmessageType))	
		if NtlmsspIdentifier != b'NTLMSSP\x00' or NTLMmessageType != b'\x01\x00\x00\x00':
			logger.error("**NTLMSSP Negotiate error")
			exit()

class NTLMSSP_auth:
	def __init__(self, buffer): 
		LanManResponse=buffer[14:14]
		NTLMResponse=buffer[20:28]
		DomainName=buffer[28:36]
		UserName=buffer[36:44]
		Hostname=buffer[44:52]
		SessionKey=buffer[52:60]
		flags=buffer[60:64]
		version=buffer[64:72]
		MIC=buffer[72:88]

##################################################################################################################
###################################    Session Setup AndX + Tree Connect Class   #################################
##################################################################################################################
    
class SessSetupAndX_TreeConn_Ans():
    ## Some field are not used because now we dont need Security
	fields_SMB_parameter1 = dict([
		("Wordcount",             "\x04"),
		("AndXCommand",           "\x75"),
		("Reserved",              "\x00"),
		("Andxoffset",            "\xb4\x00"),
		("Action",                "\x01\x00"),
		("SecBlobLen",            "\x00\x00"),
	])
	fields_SMB_data1 = dict([
		("Bcc" ,                   "\x89\x01"),
		("SSPIAccept" ,            ""),
		("NativeOs" , "Given in a Global Variable glob_natOS__"),                           
		("NativeOsTerminator" , "\x00\x00"),
		("NativeLAN" , "Given in a Global Variable glob_natLAN__"),
		("NativeLANTerminator" , "\x00\x00"),    
	])
	fields_SMB_parameter2 = dict([
		("Wordcount", "\x07"),
		("AndXCommand", "\xff"),
		("Reserved","\x00" ),
		("Andxoffset", "\xbd\x00"),
		("OptionalSupport","\x00\x00"),
		("MaxShareAccessRight","\xff\x01\x1f\x00"),
		("GuestShareAccessRight","\xff\x01\x1f\x00"),
	])
	fields_SMB_data2 = dict([
		("Bcc", "\x94\x00"),
		("Service", "A"),
		("ServiceTerminator","\x00\x00\x00\x00"),      
	])

	def __init__(self, paquet):
		pass
 
	def calculate(self):
        ##Make Native OS and Native LAN compatible with standards
		natOS_=''
		for letter in glob_natOS__ :     
			letter=letter+'\x00'
			natOS_+=letter
		self.fields_SMB_data1["NativeOs"]=natOS_
		natLAN_=''
		for letter in glob_natLAN__ :   
			letter=letter+'\x00'
			natLAN_+=letter
		self.fields_SMB_data1["NativeLAN"]=natLAN_

        ##Convert first...
		domain_f = self.fields_SMB_data1["NativeOs"].encode("ISO-8859-1")
		server_f = self.fields_SMB_data1["NativeLAN"].encode("ISO-8859-1")

        ##Then calculate BCC1 for sess_setup
		CompleteBCCLen =  self.fields_SMB_data1["SSPIAccept"]+self.fields_SMB_data1["NativeOs"]+\
								self.fields_SMB_data1["NativeOsTerminator"] + self.fields_SMB_data1["NativeLAN"]\
								+self.fields_SMB_data1["NativeLANTerminator"]
		self.fields_SMB_data1["Bcc"] = pack("<H",len(CompleteBCCLen))
        
        ##Calculate Andxoffset = len(SMB Header + SMB Param Session AndX + SMB Data Session AndX)     
		AndXOffset = 32 + 9 + 2 + len(CompleteBCCLen)
		self.fields_SMB_parameter1["Andxoffset"] = pack("<H",AndXOffset)

		##Security Blob Length Calculation
		self.fields_SMB_parameter1["SecBlobLen"] = pack("<H",len(self.fields_SMB_data1["SSPIAccept"]))

		##Then reconvert..
		self.fields_SMB_data1["Bcc"] = string(self.fields_SMB_data1["Bcc"], "ISO-8859-1")
		self.fields_SMB_parameter1["SecBlobLen"] = string(self.fields_SMB_parameter1["SecBlobLen"], "ISO-8859-1")
		self.fields_SMB_parameter1["Andxoffset"] = string(self.fields_SMB_parameter1["Andxoffset"], "ISO-8859-1")
		self.fields_SMB_data2["Service"]="IPC"

		## Complete Packet Len
		CompletePacket= string(self.fields_SMB_parameter2["Wordcount"])+ \
							string(self.fields_SMB_parameter2["AndXCommand"])+ string(self.fields_SMB_parameter2["Reserved"])\
							+ string(self.fields_SMB_parameter2["Andxoffset"]) + string(self.fields_SMB_parameter2["OptionalSupport"])\
							+ string(self.fields_SMB_parameter2["MaxShareAccessRight"]) \
							+ string(self.fields_SMB_parameter2["GuestShareAccessRight"]) + string(self.fields_SMB_data2["Bcc"]) \
							+ string(self.fields_SMB_data2["Service"]) +string(self.fields_SMB_data2["ServiceTerminator"])

		## AndXOffset2
		self.fields_SMB_parameter2["Andxoffset"] = pack("<H", (len(CompletePacket)+AndXOffset))

		## BCC Len Calc
		BccLen= string(self.fields_SMB_data2["Service"])+string(self.fields_SMB_data2["ServiceTerminator"])
		self.fields_SMB_data2["Bcc"] = pack("<H", len(BccLen))

		##Then reconvert..
		self.fields_SMB_data2["Bcc"] = string(self.fields_SMB_data2["Bcc"], "ISO-8859-1")
		self.fields_SMB_parameter2["Andxoffset"] = string(self.fields_SMB_parameter2["Andxoffset"], "ISO-8859-1")

	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()
		SMB_Param_str1 = self.fields_SMB_parameter1["AndXCommand"] \
							 + self.fields_SMB_parameter1["Reserved"] + self.fields_SMB_parameter1["Andxoffset"] \
							 + self.fields_SMB_parameter1["Action"] + self.fields_SMB_parameter1["SecBlobLen"]

		self.fields_SMB_parameter1["Wordcount"] = pack("<B",int(len(SMB_Param_str1)/2))
		self.fields_SMB_parameter1["Wordcount"] = string(self.fields_SMB_parameter1["Wordcount"], "ISO-8859-1")

		SMB_Data_str1 = self.fields_SMB_data1["Bcc"] + self.fields_SMB_data1["SSPIAccept"] \
							+ self.fields_SMB_data1["NativeOs"] + self.fields_SMB_data1["NativeOsTerminator"] \
							+ self.fields_SMB_data1["NativeLAN"] + self.fields_SMB_data1["NativeLANTerminator"]

		packetBody_str1 = self.fields_SMB_parameter1["Wordcount"] + SMB_Param_str1 + SMB_Data_str1
		packetBody_bytes1=bytes2((packetBody_str1), "ISO-8859-1")
				
		SMB_Param_str2 = self.fields_SMB_parameter2["Wordcount"] + self.fields_SMB_parameter2["AndXCommand"] \
							 + self.fields_SMB_parameter2["Reserved"] + self.fields_SMB_parameter2["Andxoffset"] \
							 + self.fields_SMB_parameter2["OptionalSupport"] + self.fields_SMB_parameter2["MaxShareAccessRight"] \
							 + self.fields_SMB_parameter2["GuestShareAccessRight"]

		SMB_Data_str2 = self.fields_SMB_data2["Bcc"] + self.fields_SMB_data2["Service"] \
								+ self.fields_SMB_data2["ServiceTerminator"]

		packetBody_str2 = SMB_Param_str2 + SMB_Data_str2
		packetBody_2in1_str = packetBody_str1 + packetBody_str2
		packetBody_2in1_bytes=bytes2((packetBody_2in1_str), "ISO-8859-1")

		return status, packetBody_2in1_bytes, len(packetBody_str)

##################################################################################################################
###################################    Echo Response to echo resquest (ping)   ###################################
##################################################################################################################

class SMB_EchoResponse:
	fields_SMB_data = dict([
		("WordCount",		"\x01"),
		("EchoCount",		"\x01\x00"),
		("BCC",				"\x10\x00"),
		("EchoData",		"\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0"),
	])
	
	def __init__(self, paquet):
		pass

	def create_p_body(self):
		status = STATUS_SUCCESS
		packetbody=self.fields_SMB_data["WordCount"]+self.fields_SMB_data["EchoCount"]\
					+self.fields_SMB_data["BCC"]+self.fields_SMB_data["EchoData"]
		return status, bytes2((packetbody), "ISO-8859-1"), len(packetbody)

##################################################################################################################
###################################   Disk Information class  ####################################################
##################################################################################################################

class SMB_DiskResponse: 
	fields_SMB_data = dict([
		("WordCount",	"\x05"),
		("TotalUnits",	"\x33\x9f"),
		("BPU",			"\x00\x10"),
		("BlockSize",	"\x00\x04"),
		("FreeUnits",	"\xcf\x41"),
		("Reserved",	"\x00\x00"),
		("BCC",			"\x00\x00"),
	])

	def __init__(self, paquet):
		pass

	def calculate(self):
		os_vers = platform
		curdir = glob_curdir
		if os_vers == 'linux2' or os_vers == 'darwin':
			infos=string(check_output("df " +curdir + "| egrep -v Filesystem | sed -e 's/ [ \t]*/ /g' | cut -d ' ' -f 2,4 ", shell=True), "ISO-8859-1")
			#infos=string(check_output("df " +curdir + "| egrep '^/' | sed -e 's/ \+/ /g' | cut -d ' ' -f 2,4 ", shell=True), "ISO-8859-1")
			infos=infos.strip('\n').split(' ')
			total=infos[0]
			available = infos[1]
			total = int(total)//4096
			available = int(available)//4096
			self.fields_SMB_data["TotalUnits"] = string(pack("<H", total), "ISO-8859-1")
			self.fields_SMB_data["FreeUnits"] = string(pack("<H", available), "ISO-8859-1")
			logger.info("total : %i" % total)
			logger.info("Free : %i" % available)
		elif os_vers == 'win32':
			drive=curdir
			fso=com.Dispatch("Scripting.FileSystemObject")
			drv=fso.GetDrive(drive)
			drv.TotalSize
			drv.FreeSpace

	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()
		packetbody=self.fields_SMB_data["WordCount"]+self.fields_SMB_data["TotalUnits"]+\
						self.fields_SMB_data["BPU"]+ self.fields_SMB_data["BlockSize"]+\
						self.fields_SMB_data["FreeUnits"]+self.fields_SMB_data["Reserved"]+\
						self.fields_SMB_data["BCC"]
		return status, bytes2((packetbody), "ISO-8859-1"), len(packetbody)

##################################################################################################################
###################################   Logoff class : user logoff #################################################
##################################################################################################################

class Logoff():
	fields_SMB_data = dict([
		("WordCount",		"\x02"),
		("AndXCommand",	"\xff"),
		("Reserved",		"\x00"),	
		("AndXOffset",		"\x27\x00"),
		("BCC",				"\x00\x00"),
		])

	def __init__(self, paquet):
		pass

	def create_p_body(self):
		status = STATUS_SUCCESS
		packetbody=self.fields_SMB_data["WordCount"]+self.fields_SMB_data["AndXCommand"]\
						+self.fields_SMB_data["Reserved"]+self.fields_SMB_data["AndXOffset"]\
						+self.fields_SMB_data["BCC"]
		return status, bytes2((packetbody), "ISO-8859-1"), len(packetbody)

##################################################################################################################
###################################   Old Trans request // not supported  ########################################
##################################################################################################################

class NTTrans:

	def __init__(self, paquet):
		pass

	def create_p_body(self):
		return reterror(STATUS_NOT_SUPPORTED)

##################################################################################################################
###################################   Close SMB request ##########################################################
##################################################################################################################

class CloseRequest:
	fields_SMB_data = dict([
		("Close",		"\x00\x00\x00"),
	])

	def __init__(self, paquet):
		pass

	def create_p_body(self):
		status = STATUS_SUCCESS
		packetbody = self.fields_SMB_data["Close"]
		return status, bytes2((packetbody), "ISO-8859-1"), len(packetbody)

##################################################################################################################
###################################   Tree disconnect     ########################################################
##################################################################################################################

class TreeDisc:
	fields_SMB_data = dict([
		("Close",		"\x00\x00\x00"),
	])

	def __init__(self, paquet):
		pass

	def create_p_body(self):
		status = STATUS_SUCCESS
		packetbody = self.fields_SMB_data["Close"]
		return status, bytes2((packetbody), "ISO-8859-1"), len(packetbody)

##################################################################################################################
################################### Transaction2 Class with many Subcommands  ####################################
##################################################################################################################

### Find Path 2 Subcommand

class FindPath:
	# dict fields not used actualy
	fields_SMB_Trans2_parameter = dict([
		("SID",                 "\x00\x08"),
		("SearchCount",         "\x00\x00"),
		("EndOfSearch",         "\x01\x00"),
		("EaErrorOffset",       "\x00\x00"),
		("LastNameOffset",      "\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("NextOffset",          "\x00\x00\x00\x00"),
		("FileIndex",           "\x00\x00\x00\x00"),
		("CreatedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastAcessDate",       "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastWriteDate",       "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("ChangedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("EndOfFile",           "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("AllocationSize",      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("FileAttribute",       "\x00\x00\x00\x00"),
		("FileNameLen",         "\x00\x00\x00\x00"),
		("EAListLen",           "\x00\x00\x00\x00"),
		("ShortFileNameLen",    "\x00"),
		("Reserved",            "\x00"),
		("ShortFileName",       "\x00\x00\x00\x00\x00\x00\x00\x00" \
										"\x00\x00\x00\x00\x00\x00\x00\x00" \
										"\x00\x00\x00\x00\x00\x00\x00\x00" \
										"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("FileName",            "\x00\x00"),
	])

	def __init__(self, level, count, pattern):
		os_vers = platform
		logger.info("findpath level : %s (%s)" % (byte2print(level), hex(unpack('H', level)[0])))
		self.level=level
		self.LastFileLen = 0
		self.count = count
		if os_vers == 'linux2' or os_vers == 'darwin':
			self.pattern=pattern.replace('\\', '/')
		elif os_vers == 'win32':
			self.pattern=pattern	
		logger.info("pattern : %s" % self.pattern)
		self.searchCount = 0

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["SID"] + self.fields_SMB_Trans2_parameter["SearchCount"] \
						+ self.fields_SMB_Trans2_parameter["EndOfSearch"] + \
						 self.fields_SMB_Trans2_parameter["EaErrorOffset"] +  self.fields_SMB_Trans2_parameter["LastNameOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		## Search in current directory with pattern
		shares = glob(glob_curdir+self.pattern)
		completePacket=''
		self.searchCount = len(shares)
		if self.searchCount ==0 and not os.path.exists(glob_curdir+self.pattern[-2]):
			logger.info("**No such file in the path with : %s" % glob_curdir+self.pattern)
			return STATUS_NO_SUCH_FILE

		if self.searchCount ==0 and os.path.exists(glob_curdir+self.pattern[-2]):
			shares =['.', '..']
			self.searchCount = 2

		for i in range(0, len(shares)):
			s=''
			share=shares[i]
			logger.info("share : %s" % share)
			if shares != ['.', '..']:
				share=share[len(glob_curdir)+1:]
				share = share.split("\\")[-1]
				share = share.split("/")[-1]
			for letter in share :
				s += letter + '\x00'
	      ## File Name is now compatible with standard (\x00 between char)
			fileName=s
			logger.debug("share in zeroid : %s" % byte2print(fileName))

			## sizeof(filename) 
			fileNameLen=pack("<I", len(fileName))
			fileNameLen=string(fileNameLen, "ISO-8859-1")

			## file attributes
			f_stat=os.lstat(shares[i])
			lastAccessDate=time_funct(f_stat[7])
			lastWriteDate=time_funct(f_stat[8])
			createdDate=time_funct(f_stat[9])
			changedDate=lastWriteDate

			## Allocation Size 
			allocationSize=pack("<Q", (f_stat[6] // 4096 +1 ) * 4096 )

			## File Attribute ! only dir/file ... add hidden ? readonly ? system ?
			fileAttribute="\x80\x00\x00\x00"
			if(os.path.isdir(shares[i])):
				fileAttribute="\x10\x00\x00\x00"

			## EOF
			EOF=pack("<Q", f_stat[6])

			## File Index # MUST be set to zero in response
			fileIndex="\x00\x00\x00\x00"

			## EA List Len  !! not used
			eaListLen="\x00\x00\x00\x00"

			## Short File Name Len !! not used
			shortFileNameLen="\x00"

			## Reserved
			reserved="\x00"

			## Short File Name !! not used
			shortFileName="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

			## Sub Packet [i]
			subPacket_str=""
			if self.level==SMB_LEVEL_FIND_INF0_BOTH:
				subPacket_str = string(fileIndex) + string(createdDate, "ISO-8859-1") + \
									string(lastAccessDate, "ISO-8859-1") + string(lastWriteDate, "ISO-8859-1") \
								 + string(changedDate, "ISO-8859-1") + string(EOF, "ISO-8859-1") + \
									string(allocationSize, "ISO-8859-1") + string(fileAttribute) + \
									string(fileNameLen) + string(eaListLen) \
								 + string(shortFileNameLen) + string(reserved) + string(shortFileName) +fileName
			elif self.level== SMB_LEVEL_FIND_INF0_FULL:
				subPacket_str = string(fileIndex) + string(createdDate, "ISO-8859-1") + \
									string(lastAccessDate, "ISO-8859-1") + string(lastWriteDate, "ISO-8859-1") \
								 + string(changedDate, "ISO-8859-1") + string(EOF, "ISO-8859-1") + \
									string(allocationSize, "ISO-8859-1") + string(fileAttribute) + \
									string(fileNameLen) + string(eaListLen) + fileName
				
			## Next Offset
			nextOffset = 4 + len(subPacket_str)
			self.LastFileLen = self.LastFileLen + nextOffset
			nextOffset = pack("<I", nextOffset)

			## Next Offset
			subPacketComp_str = string(nextOffset,"ISO-8859-1") + subPacket_str

			## Concat all in one packet
			completePacket+=subPacketComp_str

		return completePacket

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		## SID !! A completer
		sid="\x00\x08"
		## Search Count
		searchCount=pack("<H", self.searchCount)
		searchCount=string(searchCount, "ISO-8859-1")
		## End Of Search : \x00\x00 -> not ended else ended
		endOfSearch="\x10\x00"
		## EaErrorOffset !!
		EaErrorOffset="\x00\x00"
		## Last Name Offset
		LastNameOffset = self.LastFileLen
		logger.info("Packet Len : %i" % packetLen )
		logger.info("lastnameoffset : %i" % LastNameOffset)
		logger.info("dataoffset : %i" % dataOffset)
		logger.info("lastfilelen : %i" % self.LastFileLen)
		LastNameOffset = pack("<H", LastNameOffset)
		LastNameOffset = string(LastNameOffset, "ISO-8859-1")
		## Trans2_parameter
		trans2_param_str = sid + searchCount + endOfSearch + EaErrorOffset + LastNameOffset

		return trans2_param_str   

### Query File Info SubCommand

class QueryFile:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])

	fields_SMB_Trans2_data = dict([
		("CreatedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastAccessDate",      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastWriteDate",       "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("ChangedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("FileAttribute",       "\x20\x00\x00\x00"),
		("Reserved",				"\x00\x00\x00\x00"),
		("AllocationSize",      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("EndOfFile",           "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LinkCount",				"\x01\x00\x00\x00"),
		("DeletePending",			"\x00"),
		("IsDirectory",			"\x00"),
		("Reserved2",				"\x00\x00"),
		("EAListLen",           "\x00\x00\x00\x00"),
		("FileNameLen",         "\x00\x00\x00\x00"),
		("FileName",            "\x00\x00"),
	])

	def __init__(self, filename):
		self.filename = filename

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		file_stat = os.lstat(self.filename)
		createdDate=time_funct(file_stat[9])
		lastAccessDate=time_funct(file_stat[7])
		lastWriteDate=time_funct(file_stat[8])
		changedDate=lastWriteDate
		if(os.path.isdir(self.filename)):
				FileAttribute="\x10\x00\x00\x00"
		else:
				FileAttribute="\x00\x00\x00\x00"
		Reserved = "\x00\x00\x00\x00"
		EOF = pack("<Q", file_stat[6])
		AllocationSize = pack("<Q", (file_stat[6] // 4096 + 1 ) * 4096)
		LinkCount = pack("<I", file_stat[3])
		DeletePending = pack("B", 0)
		if(os.path.isdir(self.filename)):
			IsDirectory= pack("B", 1)
		else:
			IsDirectory= pack("B", 0)
		Reserved2 = "\x00\x00"
		EAListLen = pack("<I", 0)
		FileName = strTobytes2('\\' +	self.filename)[0]
		logger.info("Filename in zeroid str : %s" % FileName)
		FileNameLen = pack("<I", len(FileName))

		logger.info("FileAttribute : %s" % hex(unpack('I', bytes2(FileAttribute	,"ISO-8859-1"))[0]))	
		logger.info("AllocationSize : %s (%i)" % (byte2print(AllocationSize), unpack('Q',AllocationSize)[0]) )
		logger.info("EOF : %s (%i)" % (byte2print(EOF), unpack('Q',EOF)[0]))		
		logger.info("LinkCount : %s (%i)" % (byte2print(LinkCount),  unpack('I',LinkCount)[0] ))		
		logger.info("DeletePending : %s" % byte2print(DeletePending))
		logger.info("IsDirectory : %s" % byte2print(IsDirectory))	
		logger.info("EAListLen : %s (%i)" % (byte2print(EAListLen),unpack('I',EAListLen )[0] ))
		logger.info("FileNameLen : %s (%i)" % (byte2print(FileNameLen), unpack('I',FileNameLen )[0] ))		

		Packet_str = string(createdDate, "ISO-8859-1") + string(lastAccessDate, "ISO-8859-1") +\
						 string(lastWriteDate, "ISO-8859-1") + string(changedDate, "ISO-8859-1") + FileAttribute + Reserved +\
						 string(AllocationSize, "ISO-8859-1") + string(EOF, "ISO-8859-1") + string(LinkCount, "ISO-8859-1") +\
						 string(DeletePending, "ISO-8859-1") + string(IsDirectory, "ISO-8859-1") + Reserved2 +\
						 string(EAListLen, "ISO-8859-1") + string(FileNameLen, "ISO-8859-1") + \
						 FileName
		
		return Packet_str

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		packet = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return packet

class QueryFileInfoStandard:
	fields__SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])

	fields_SMB_Trans2_data = dict([
		("AllocationSize",      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("EndOfFile",           "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LinkCount",				"\x01\x00\x00\x00"),
		("DeletePending",			"\x00"),
		("IsDirectory",			"\x00"),
	])

	def __init__(self, paquet):
		pass

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		pass
	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		pass

class QueryFileInternal:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("IndexNumber",      "\x06\x60\xa9\x00\x00\x00\x00\x00"),
	])

	def __init__(self, paquet):
		pass

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		return self.fields_SMB_Trans2_data["IndexNumber"]

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		return self.fields_SMB_Trans2_parameter["EAerrorOffset"] 

class QueryFileStreamInfo:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("NextEntryOffset",		"\x00\x00\x00\x00"),
		("StreamNameLength",		"\x0e\x00\x00\x00"),
		("StreamSize",				"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("AllocationSize",		"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("StreamName",				"\x00"),
	])
	
	def __init__(self, filename):
		self.filename = filename

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)
	
	def genSubPacketTrans2_data(self):
		file_stat = os.lstat(self.filename)

		self.fields_SMB_Trans2_data["StreamSize"] = string(pack("<Q", file_stat[6]), "ISO-8859-1")
		self.fields_SMB_Trans2_data["AllocationSize"] = string(pack("<Q", file_stat[6] * 4096 ), "ISO-8859-1")
		self.fields_SMB_Trans2_data["StreamName"] = strTobytes2('::$DATA')[0]
		self.fields_SMB_Trans2_data["StreamNameLength"] = pack("<I", len(self.fields_SMB_Trans2_data["StreamName"]))

		logger.info("StreamSize : %s" % self.fields_SMB_Trans2_data["StreamSize"])	
		logger.info("AllocationSize : %s" % self.fields_SMB_Trans2_data["AllocationSize"])	
		logger.info("StreamName : %s" % self.fields_SMB_Trans2_data["StreamName"])	
		logger.info("StreamNameLength : %s" % byte2print(self.fields_SMB_Trans2_data["StreamNameLength"]))

		return self.fields_SMB_Trans2_data["NextEntryOffset"] + string(self.fields_SMB_Trans2_data["StreamNameLength"], "ISO-8859-1") \
					+ self.fields_SMB_Trans2_data["StreamSize"] + self.fields_SMB_Trans2_data["AllocationSize"] \
					+ self.fields_SMB_Trans2_data["StreamName"]

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		return self.fields_SMB_Trans2_parameter["EAerrorOffset"] 

### Query Path SubCommand 
class QueryPathBasic:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("CreatedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastAccessDate",      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LastWriteDate",       "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("ChangedDate",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("FileAttribute",        "\x00\x00\x00\x00\x00\x00\x00\x00"),
	])

	def __init__(self, curdir):
		logger.info("Query Basic Info : %s" % curdir)
		self.dir=curdir

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		os_vers = platform	
		if self.dir[0] == '\\':
			self.dir=self.dir[1:]
		if os_vers == 'linux2' or os_vers == 'darwin':
			curdir=self.dir.replace('\\', '/')
		elif os_vers == 'win32':
			curdir=self.dir
		if not os.path.exists(curdir):
			logger.warning("**no such file : %s" % curdir)
			return STATUS_NO_SUCH_FILE

		dir_stat = os.lstat(curdir)
		createdDate=time_funct(dir_stat[9])
		lastAccessDate=time_funct(dir_stat[7])
		lastWriteDate=time_funct(dir_stat[8])
		changedDate=lastWriteDate
		if(os.path.isdir(curdir)):
				FileAttribute="\x10\x00\x00\x00"
				logger.info("current file is a directory : %s" % curdir)
		else:
				FileAttribute="\x00\x00\x00\x00"

		Packet_str = string(createdDate, "ISO-8859-1") + string(lastAccessDate, "ISO-8859-1") +\
						 string(lastWriteDate, "ISO-8859-1") + string(changedDate, "ISO-8859-1") + FileAttribute
		
		return Packet_str

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		packet = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return packet

class QueryFileEAInfo:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("NextEntryOffset",   "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("EANameLength",      "\x00"),
		("EAName",				 "\x00"),
	])

	def __init__(self, curdir):
		pass

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		Packet_str = self.fields_SMB_Trans2_data["NextEntryOffset"] + \
						 self.fields_SMB_Trans2_data["EANameLength"] + self.fields_SMB_Trans2_data["EAName"]
		
		return Packet_str

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		packet = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return packet

class QueryPathStandard:
	fields_SMB_Trans2_parameter = dict([
		("EAerrorOffset",			"\x00\x00"),
	])
	fields_SMB_Trans2_data = dict([
		("AllocationSize",         "\x00\x10\x00\x00\x00\x00\x00\x00"),
		("EOF",					      "\x00\x00\x00\x00\x00\x00\x00\x00"),
		("LinkCount",			      "\x01\x00\x00\x00"),
		("DeletePending",			    "\x01"),
		("IsDirectory",			    "\x00"),
		("Reserved",				    "\x00\x00"),
	])
	
	def __init__(self, dir):
		self.dir=dir

	def getSizeParameter(self):
		parameter = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return len(parameter)

	def genSubPacketTrans2_data(self):
		os_vers = platform
		if self.dir[0] == '\\':
			self.dir=self.dir[1:]	
		if os_vers == 'linux2' or os_vers == 'darwin':
			curdir=self.dir.replace('\\', '/')
		elif os_vers == 'win32':
			curdir = self.dir
		logger.info("current directory : %s" % curdir)

		if curdir == '\\srvsvc' or curdir == '/srvsvc' or curdir == 'srvsvc':
			logger.info("In the pipe !" )
			return self.fields_SMB_Trans2_data["AllocationSize"] + self.fields_SMB_Trans2_data["EOF"] + \
					self.fields_SMB_Trans2_data["LinkCount"] + self.fields_SMB_Trans2_data["DeletePending"] + \
					self.fields_SMB_Trans2_data["IsDirectory"] + self.fields_SMB_Trans2_data["Reserved"]

		if not os.path.exists(curdir):
			return STATUS_NO_SUCH_FILE

		dir_stat=os.lstat(curdir)
		EOF = pack("<Q", dir_stat[6])
		LinkCount = pack("<I", dir_stat[3]) 
		if os.path.isdir(curdir):
			IsDirectory = pack("<B", 1)
			AllocationSize = pack("<Q", 0)
		else:
			IsDirectory = pack("B", 0)
			AllocationSize = pack("<Q", (dir_stat[6] // 4096 + 1 ) * 4096)
		DeletePending = pack("B", 0)
		Reserved =pack("<H", 0)

		Packet_str = string(AllocationSize, "ISO-8859-1") + string(EOF, "ISO-8859-1") + \
						string(LinkCount, "ISO-8859-1") + string(DeletePending, "ISO-8859-1") + \
						string(IsDirectory, "ISO-8859-1") + string(Reserved,  "ISO-8859-1")
		return Packet_str

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		packet = self.fields_SMB_Trans2_parameter["EAerrorOffset"] 
		return packet

class QueryFS:
	fields_SMB_Trans2_parameter = dict([])

	fields_SMB_Trans2_data = dict([
			("FSAttribute",		"\x03\x00\x00\x00"),
			("MaxFileName",		"\xff\x00\x00\x00"),
			("LengthOfFSName",	"\x0a\x00\x00\x00"),
			("FSName",				"\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00"),
		])
	fields_SMB_Trans2_data_VOLUME = dict([
			("Created",				"\x00\x00\x00\x00\x00\x00\x00\x00"),
			("VolumeSerial",		"\x37\x33\x33\x31"),
			("LabelLength",	   "\x0a\x00\x00\x00"),
			("Reserved",			"\x00\x00"),
			("Label",				"\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00"),
		])

	def __init__ (self, data):
		self.level = data[68:70]
	
	def getSizeParameter(self):
		parameter = ""
		return 0

	def genSubPacketTrans2_data(self):
		Packet_str=''
		logger.info("level FS : %s (%i)" % (byte2print(self.level), unpack('H', self.level)[0]))
		if self.level == SMB_QUERY_FS_ATTRIBUTE_INFO:
			Packet_str = string(self.fields_SMB_Trans2_data["FSAttribute"]) + \
							string(self.fields_SMB_Trans2_data["MaxFileName"]) + \
						 string(self.fields_SMB_Trans2_data["LengthOfFSName"]) +  string(self.fields_SMB_Trans2_data["FSName"]) 
		elif self.level == SMB_QUERY_FS_VOLUME_INFO:
			f_stat = os.lstat(glob_curdir)
			createdDate=time_funct(f_stat[9])
			
			self.fields_SMB_Trans2_data_VOLUME["Created"] = string(createdDate, "ISO-8859-1")
			Packet_str = string(self.fields_SMB_Trans2_data_VOLUME["Created"]) + \
						 string(self.fields_SMB_Trans2_data_VOLUME["VolumeSerial"]) + \
						 string(self.fields_SMB_Trans2_data_VOLUME["LabelLength"]) +  \
						 string(self.fields_SMB_Trans2_data_VOLUME["Reserved"]) + \
						 string(self.fields_SMB_Trans2_data_VOLUME["Label"])

		return Packet_str

	def genSubPacketTrans2_parameter(self,packetLen,dataOffset):
		return ""

class SMB_Trans:
	fields_SMB_parameter = dict([
		("Wordcount",                     "\x0a"),
		("TotalParameterCount",           "\x00\x00"),
		("TotalDataCount",                "\x00\x00"),
		("Reserved1",                     "\x00\x00"),
		("ParameterCount",                "\x00\x00"),
		("ParameterOffset",               "\x37\x00"),
		("ParameterDisplacement",         "\x00\x00"),
		("DataCount",                     "\xa3\x00"),
		("DataOffset",                    "\x3f\x00"),
		("DataDisplacement",              "\x00\x00"),
		("SetupCount",                    "\x00"),
		("Reserved2",                     "\x00"),
	]) 
	fields_SMB_data = dict([
		("Bcc" ,       "\x8f\x00"),
		("Pad1" ,            "\x00"),
		("Trans_data[ParameterCount]" , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),                          
	])

	def __init__ (self, data):
		self.paquet = data
		self.FID = unpack("<H", data[63:65])[0]
		logger.info("FID in Trans Paquet : %i" % self.FID)
		self.function=data[61:63]
		logger.info("Transac function : %s (%i)" % (byte2print(self.function), unpack('H', self.function)[0]))
		self.dataOffset = unpack("<H", data[53:55])[0]
		self.pipe=""
		self.opnum=""

		if self.function == b'\x26\x00':
			self.pipe = data[self.dataOffset:]
			logger.info("pipe : %s" % byte2print(self.pipe))
			self.opnum = self.pipe[22:24]
			logger.info("opnum : %s (%i)" % (byte2print(self.opnum),unpack('H', self.opnum)[0]))

	def calculate(self):
		
		if self.function == WAIT_NAMED_PIPE: 
			logger.warning("WAIT_NAMED_PIPE not implemented")
			return

		if self.opnum == SMB_TRANS_NETSHAREINFO:
			logger.info("Opnum NetShareGetInfo")
			dce='\x05\x00\x02\x03\x10\x00\x00\x00' + \
				 '\x58\x00' + \
				 '\x00\x00' + \
				 '\x02\x00' + \
				 '\x00\x00' + \
				 '\x40\x00\x00\x00' +\
				 '\x00\x00\x00\x00'
			service = '\x01\x00\x00\x00\x00\x00\x02\x00' + \
						 '\x04\x00\x02\x00\x00\x00\x00\x00\x08\x00\x02\x00' + \
						 '\x06\x00\x00\x00' + '\x00\x00\x00\x00' + '\x06\x00\x00\x00' + \
						 '\x73\x00\x68\x00\x61\x00\x72\x00\x65\x00\x00\x00' + \
						 '\x01\x00\x00\x00'+ '\x00\x00\x00\x00' + '\x01\x00\x00\x00'  + \
						 '\x00\x00' + '\x00\x00\x00\x00\x00\x00'
			self.fields_SMB_data["Trans_data[ParameterCount]"]=dce + service

		self.fields_SMB_parameter["TotalDataCount"] = len(self.fields_SMB_data["Trans_data[ParameterCount]"])
		self.fields_SMB_data["Bcc"] = self.fields_SMB_parameter["TotalDataCount"] + 1
		self.fields_SMB_parameter["ParameterOffset"] = 32 + 23 +1

		self.fields_SMB_parameter["TotalDataCount"] = string(pack("<H", \
																	self.fields_SMB_parameter["TotalDataCount"]), "ISO-8859-1")
		self.fields_SMB_parameter["DataCount"] = self.fields_SMB_parameter["TotalDataCount"]
		self.fields_SMB_data["Bcc"] = string(pack("<H", self.fields_SMB_data["Bcc"]), "ISO-8859-1")
		self.fields_SMB_parameter["ParameterOffset"] = string(pack("<H", self.fields_SMB_parameter["ParameterOffset"]), \
																	"ISO-8859-1")
		self.fields_SMB_parameter["DataOffset"] = self.fields_SMB_parameter["ParameterOffset"]
		

	def create_p_body(self):
		status = STATUS_SUCCESS
		if self.function == WAIT_NAMED_PIPE: 
			logger.warning("WAIT_NAMED_PIPE not implemented")
			return reterror(STATUS_NOT_SUPPORTED)

		self.calculate()
		SMB_Param_str = self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["TotalParameterCount"] \
							 + self.fields_SMB_parameter["TotalDataCount"] + self.fields_SMB_parameter["Reserved1"] \
							 + self.fields_SMB_parameter["ParameterCount"] + self.fields_SMB_parameter["ParameterOffset"] \
							 + self.fields_SMB_parameter["ParameterDisplacement"] + self.fields_SMB_parameter["DataCount"] \
							 + self.fields_SMB_parameter["DataOffset"] + self.fields_SMB_parameter["DataDisplacement"] \
							 + self.fields_SMB_parameter["SetupCount"] + self.fields_SMB_parameter["Reserved2"] 

		SMB_Data_str = self.fields_SMB_data["Bcc"] + self.fields_SMB_data["Pad1"] \
							+ self.fields_SMB_data["Trans_data[ParameterCount]"]

		packetBody_str = SMB_Param_str + SMB_Data_str

		packetBody_bytes=bytes2((packetBody_str), "ISO-8859-1")
		return status, packetBody_bytes, len(packetBody_str)

class SMB_Trans2():
    ## Some field are not used because now we dont need Security
	fields_SMB_parameter = dict([
		("Wordcount",                     "\x0a"),
		("TotalParameterCount",           "\x0a\x00"),
		("TotalDataCount",                "\x08\x0a"),
		("Reserved1",                     "\x00\x00"),
		("ParameterCount",                "\x0a\x00"),
		("ParameterOffset",               "\x37\x00"),
		("ParameterDisplacement",         "\x00\x00"),
		("DataCount",                     "\xa3\x00"),
		("DataOffset",                    "\x3f\x00"),
		("DataDisplacement",              "\x00\x00"),
		("SetupCount",                    "\x00"),
		("Reserved2",                     "\x00"),
		("Setup[SetupCount]",             ""),
	]) 
	fields_SMB_data = dict([
		("Bcc" ,       "\x8f\x00"),
		("Pad1" ,            "\x00"),
		("Trans_Parameters[ParameterCount]" , "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),                          
		("Pad2" , "\x00\x00"),
		("Trans_Data[DataCount]" , ""),
	])

	def __init__(self, paquet):
		self.cmd=getSubCmd(paquet)
		self.level=0
		self.curfile=''
		self.error=STATUS_SUCCESS
		self.paquet = paquet

		if self.cmd == SMB_TRANS2_QUERYPATH:
			self.level=getLevelInfo(paquet)
			tmpfile=bytesTostring(paquet[74:])
			logger.info("Query Path Info, file : %s" % tmpfile)
			if tmpfile == '':
				self.curfile=glob_curdir
			else:
				if tmpfile[0] == '\\' or tmpfile[0] == '/':
					self.curfile=tmpfile[1:]
				else:
					self.curfile=tmpfile
				if not os.path.exists(self.curfile):
					self.error = STATUS_OBJECT_NAME_NOT_FOUND

		elif self.cmd==SMB_TRANS2_QUERYFILEINFO:
			self.level=getLevelFileInfo(paquet)
			tmpfile=unpack("<H", getLevelInfo(paquet))[0]  # bad name fr this function due to code reuse
			logger.info("file index : %s" % string(tmpfile))
			try: 
				self.curfile=glob_Files[string(tmpfile)][0]
			except KeyError:
				self.error = STATUS_NOT_FOUND
			logger.info("levelFile Info : %s (%i)" % (byte2print(self.level), unpack('H', self.level)[0]))
		elif self.cmd==SMB_TRANS2_FIND2:
			self.level=getLevelFindInfo(paquet)
			self.searchCount = paquet[70:72]
			self.pattern = bytesTostring(paquet[80:])
			logger.info("find level/pattern : %s %s" % (byte2print(self.level) , self.pattern))

	def calculate(self):
		## Generate Trans2_data
		if self.error == STATUS_NOT_FOUND:
			return
		if self.cmd==SMB_TRANS2_FIND2:
			logger.info("Trans2 subcommand : Find first2")
			trans2=FindPath(self.level, self.searchCount, self.pattern)
		#elif self.cmd==SMB_TRANS2_QUERYFILE:
		#	pass
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_INFO_STANDARD:
			logger.info("Trans2 subcommand : Query File Info / Level info standard")
			trans2=QueryPathStandard(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_ALL_INFO:
			logger.info("Trans2 subcommand : Query File Info / Level all info ")
			trans2=QueryFile(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_INTERNAL_INFO:
			logger.info("Trans2 subcommand : Query File Info / Level internal info ")
			trans2=QueryFileInternal(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_INFO_BASIC:
			logger.info("Trans2 subcommand : Query File Info / Level basic info ")
			trans2=QueryPathBasic(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_EA_INFO:
			logger.info("Trans2 subcommand : Query File Info / Level EA info ")
			trans2=QueryFileEAInfo(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFILEINFO and self.level==SMB_LEVEL_FILE_STREAM_INFO:
			logger.info("Trans2 subcommand : Query File Info / Level file stream info ")
			trans2=QueryFileStreamInfo(self.curfile)
		elif self.cmd==SMB_TRANS2_DFSREF: # DFS Error
			logger.info("Trans2 subcommand : DFS ")
			return
		elif self.cmd==SMB_TRANS2_QUERYPATH and self.level==SMB_LEVEL_INFO_BASIC:
			logger.info("Trans2 subcommand : Query Path Info / Level basic info ")
			trans2=QueryPathBasic(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYPATH and self.level==SMB_LEVEL_INFO_STANDARD:
			logger.info("Trans2 subcommand : Query Path Info / Level info standard")
			trans2=QueryPathStandard(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYPATH and self.level==SMB_LEVEL_INTERNAL_INFO:
			logger.info("Trans2 subcommand : Query Path Info / Level internal info ")
			trans2=QueryPathStandard(self.curfile) # FTFM (find the..)
		elif self.cmd==SMB_TRANS2_QUERYPATH and self.level==SMB_LEVEL_EA_INFO:
			logger.info("Trans2 subcommand : Query Path Info / Level EA info ")
			trans2=QueryFileEAInfo(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYPATH and self.level==SMB_LEVEL_FILE_BASIC_INFO:
			logger.info("Trans2 subcommand : Query Path Info / Level file basic info ")
			trans2=QueryPathBasic(self.curfile)
		elif self.cmd==SMB_TRANS2_QUERYFS:
			logger.info("Trans2 subcommand : Query FileSystem ")
			trans2=QueryFS(self.paquet)
		else:
			logger.error("**command not implemented command : %s level : %s" %  (byte2print(self.cmd), byte2print(self.level)))
			exit()

		trans2_data=trans2.genSubPacketTrans2_data()
		if trans2_data == STATUS_NO_SUCH_FILE:
			return STATUS_NO_SUCH_FILE
		self.fields_SMB_data["Trans_Data[DataCount]"]=trans2_data
			 
		## Calculate Data Count
		self.fields_SMB_parameter["DataCount"] = pack("<H", len(trans2_data))
		self.fields_SMB_parameter["DataCount"] = string(self.fields_SMB_parameter["DataCount"], "ISO-8859-1")

		## Calculate Total Data Count 
		self.fields_SMB_parameter["TotalDataCount"] = self.fields_SMB_parameter["DataCount"]
	
		## Complete Packet Len
		CompletePacket= string(self.fields_SMB_parameter["Wordcount"])+ \
							string(self.fields_SMB_parameter["TotalParameterCount"])+ \
							string(self.fields_SMB_parameter["TotalDataCount"])\
							 +string(self.fields_SMB_parameter["Reserved1"]) + \
							string(self.fields_SMB_parameter["ParameterCount"])+ \
							string(self.fields_SMB_parameter["ParameterOffset"]) \
							 +string(self.fields_SMB_parameter["ParameterDisplacement"]) + \
							string(self.fields_SMB_parameter["DataCount"]) + \
							string(self.fields_SMB_parameter["DataOffset"]) \
							 +string(self.fields_SMB_parameter["DataDisplacement"]) +\
							 string(self.fields_SMB_parameter["SetupCount"]) +\
							 string(self.fields_SMB_parameter["Reserved2"]) \
							 +string(self.fields_SMB_parameter["Setup[SetupCount]"])+ \
							string(self.fields_SMB_data["Bcc"]) + string(self.fields_SMB_data["Pad1"]) \
							 +string(self.fields_SMB_data["Trans_Parameters[ParameterCount]"]) + \
							string(self.fields_SMB_data["Pad2"]) + string(self.fields_SMB_data["Trans_Data[DataCount]"])
		## Calculate ParameterOffset --> 32 : SMB Header Len cte
		Param_Offset= 32 + len(CompletePacket) - len( string(self.fields_SMB_data["Trans_Data[DataCount]"]) \
						+ string(self.fields_SMB_data["Trans_Parameters[ParameterCount]"])  + string(self.fields_SMB_data["Pad2"]))
		self.fields_SMB_parameter["ParameterOffset"] = pack("<H", Param_Offset)

		## Calculate DataOffset
		Data_Offset= Param_Offset + trans2.getSizeParameter() +2
		self.fields_SMB_parameter["DataOffset"] = pack("<H", Data_Offset)

		## BCC Len Calc
		BccLen= len(string(self.fields_SMB_data["Pad1"])) +len(string(self.fields_SMB_data["Trans_Parameters[ParameterCount]"])) \
				  + len(string(self.fields_SMB_data["Pad2"])) + len(string(self.fields_SMB_data["Trans_Data[DataCount]"]))
		self.fields_SMB_data["Bcc"] = pack("<H", BccLen)

		## Generate Trans2_param
		trans2_param = trans2.genSubPacketTrans2_parameter(len(CompletePacket),Data_Offset)
		self.fields_SMB_data["Trans_Parameters[ParameterCount]"]= trans2_param
		self.fields_SMB_parameter["TotalParameterCount"] = len(trans2_param)
		self.fields_SMB_parameter["TotalParameterCount"] = string(pack("<H", self.fields_SMB_parameter["TotalParameterCount"]), "ISO-8859-1")
		self.fields_SMB_parameter["ParameterCount"] = self.fields_SMB_parameter["TotalParameterCount"] 

		##Then reconvert..
		self.fields_SMB_data["Bcc"] = string(self.fields_SMB_data["Bcc"], "ISO-8859-1")
		self.fields_SMB_parameter["DataOffset"] = string(self.fields_SMB_parameter["DataOffset"], "ISO-8859-1")
		self.fields_SMB_parameter["ParameterOffset"] = string(self.fields_SMB_parameter["ParameterOffset"], "ISO-8859-1")
        
	def create_p_body(self):
		status = STATUS_SUCCESS
		if self.cmd==SMB_TRANS2_DFSREF:
			logger.warning("SMB_TRANS2_DFSREF : not implemented, return error")
			return reterror(STATUS_NOT_FOUND)
		if self.error == STATUS_NOT_FOUND:
			logger.error("STATUS_NOT_FOUND")
			return reterror(STATUS_NOT_FOUND)

		if self.calculate() == STATUS_NO_SUCH_FILE:
			logger.error("STATUS_NO_SUCH_FILE")
			return reterror(STATUS_NO_SUCH_FILE)

		SMB_Param_str = self.fields_SMB_parameter["TotalParameterCount"] \
							 + self.fields_SMB_parameter["TotalDataCount"] + self.fields_SMB_parameter["Reserved1"] \
							 + self.fields_SMB_parameter["ParameterCount"] + self.fields_SMB_parameter["ParameterOffset"] \
							 + self.fields_SMB_parameter["ParameterDisplacement"] + self.fields_SMB_parameter["DataCount"] \
							 + self.fields_SMB_parameter["DataOffset"] + self.fields_SMB_parameter["DataDisplacement"] \
							 + self.fields_SMB_parameter["SetupCount"] + self.fields_SMB_parameter["Reserved2"] \
							 + self.fields_SMB_parameter["Setup[SetupCount]"]

		SMB_Data_str = self.fields_SMB_data["Bcc"] + self.fields_SMB_data["Pad1"] + self.fields_SMB_data["Trans_Parameters[ParameterCount]"] \
							+ self.fields_SMB_data["Pad2"] + self.fields_SMB_data["Trans_Data[DataCount]"]

		self.fields_SMB_parameter["Wordcount"] = pack("<B",int(len(SMB_Param_str)/2))
		self.fields_SMB_parameter["Wordcount"] = string(self.fields_SMB_parameter["Wordcount"], "ISO-8859-1")

		packetBody_str = self.fields_SMB_parameter["Wordcount"] + SMB_Param_str + SMB_Data_str

		logger.debug("Packet Trans2 sent : %s" % packetBody_str)
		packetBody_bytes=bytes2((packetBody_str), "ISO-8859-1")
		return status, packetBody_bytes, len(packetBody_str)

##################################################################################################################
###################################    Open AndX Response Class : open a SMB resource ############################
##################################################################################################################

class SMB_Open_AndX_Ans():
	fields_SMB_parameter = dict([
		("Wordcount",    "\x0f"),
		("AndXCommand",  "\xff"),
		("AndXReserved", "\x00" ),
		("Andxoffset",   "\x41\x00"),
		("FID",          "\x00\x50"),
		("FileAttrs",    "\x00\x00"),
		("LastWriteTime","\x00\x00\x00\x00"),
		("FileDataSize", "\x00\x00\x00\x00"),
		("AccessRights", "\x00\x00"),
		("ResourceType", "\x00\x00"),
		("NMPipeStatus", "\x00\x00"),
		("OpenResults",  "\x01\x00"),
		("ServerFID",    "\x00\x00\x00\x00"),
		("Reserved",     "\x00\x00"),
	])
	fields_SMB_data = dict([
		("Bcc" ,         "\x00\x00"),
	])

	def __init__(self, data):
		self.AccessMode=unpack('H', data[39:41])[0]
		self.SearchAttr=unpack('H', data[41:43])[0]
		self.FileAttr=data[43:45]
		self.OpenFct=data[49:51]
		self.name=bytesTostring(data[66:])
		if self.name[0] == '\\':
			self.name=self.name[1:]

		os_vers = platform
		if os_vers == 'linux2' or os_vers == 'darwin':
				self.name=self.name.replace('\\', '/')

		logger.info("Access Mode : %i" % self.AccessMode)
		logger.info("Search Attributes : %i" % self.SearchAttr)
		logger.info("File Attributes : %s" % byte2print(self.FileAttr))
		logger.info("Open : %s (%i)" % (byte2print(self.OpenFct),  unpack('H', self.OpenFct)[0]) )
		logger.info("File name : %s" % self.name)

	def create_p_body(self):
		status = STATUS_SUCCESS

		# if open and search type = file and real file is directory return error
		if ((self.AccessMode & 0x0007) == 0 or (self.AccessMode & 0x0007) == 2) \
			and os.path.isdir(self.name) \
			and (self.SearchAttr & 0x8 == 0):
				return reterror(STATUS_FILE_IS_A_DIRECTORY)
	
		# STATUS_DENIED if access is not allowed

		# if not exist
		logger.info("AccessMode & 0x0007 : %i" % (self.AccessMode & 0x0007))
		logger.info("Is File : %s" % os.path.isfile(self.name))
		if (self.AccessMode & 0x0007) == 0 and not os.path.isfile(self.name):
			logger.error("STATUS_OBJECT_NAME_NOT_FOUND : %s", self.name)
			return reterror(STATUS_OBJECT_NAME_NOT_FOUND)
		
		# if ok set an FID
		global glob_Files
		global glob_FID
		fid = glob_FID
		glob_Files[string(glob_FID)] = [self.name, 0]
		glob_FID = glob_FID + 1
		logger.info("Files tab : %s" % glob_Files )
		self.fields_SMB_parameter["FID"] = string(pack("<H", fid), "ISO-8859-1")
		f_stat=os.lstat(self.name)

		self.fields_SMB_parameter["LastWriteTime"] = string(pack('I', f_stat[8]), "ISO-8859-1")
		self.fields_SMB_parameter["FileDataSize"] = string(pack('I', f_stat[6]), "ISO-8859-1")

		SMB_Param_Data_str = self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["AndXCommand"] \
            + self.fields_SMB_parameter["AndXReserved"] + self.fields_SMB_parameter["Andxoffset"] \
            + self.fields_SMB_parameter["FID"] + self.fields_SMB_parameter["FileAttrs"] \
            + self.fields_SMB_parameter["LastWriteTime"] + self.fields_SMB_parameter["FileDataSize"] \
            + self.fields_SMB_parameter["AccessRights"] + self.fields_SMB_parameter["ResourceType"] \
            + self.fields_SMB_parameter["NMPipeStatus"] + self.fields_SMB_parameter["OpenResults"] \
            + self.fields_SMB_parameter["ServerFID"] + self.fields_SMB_parameter["Reserved"] \
            + self.fields_SMB_data["Bcc"]

		packetBody_bytes=bytes2((SMB_Param_Data_str), "ISO-8859-1")
		return status, packetBody_bytes, len(SMB_Param_Data_str)

##################################################################################################################
###################################   CreateX Class : open or create a SMB resource  #############################
##################################################################################################################

class CreateX:
	fields_SMB_parameter = dict([
		("Wordcount",		"\x2a"),
		("AndXCommand",	"\xff"),
		("AndXReserved",	"\x00" ),
		("Andxoffset",		"\x00\x00"),
		("OplockLevel",	"\x00"),
		("FID",				"\x00\x00"),
		("CreateAction",	"\x01\x00\x00\x00"), #until server is read only
		("Created",			b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("LastAccess",		b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("LastWrite",		b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("Change",			b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("FileAttribute",	"\x80\x00\x00\x00"),
		("AllocationSize",b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("EOF",				b'\x00\x00\x00\x00\x00\x00\x00\x00'),
		("FileType",		"\x00\x00"),
		("IPCstate",		"\xff\x05"),
		("Directory",		"\x00\x00"),
	])
	fields_SMB_data = dict([
		("Bcc" ,         "\x00\x00"),
		("Pad1",			  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), # dunno wtf these pads are necessary
		("Pad2",			  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), # not in doc nor in Samba' source code 
		("Pad3",			  "\xff\x01\x1f\x09\x9b\x01\x12\x00\x00\x00"),
	])

	def __init__(self, paquet): #filename, piped):
		filename = getNameFile(paquet)
		os_vers = platform
		if filename=='':
			filename=glob_curdir
		if filename[0] == '\\':
			filename=filename[1:]
		if os_vers == 'linux2' or os_vers == 'darwin':
				self.filename=filename.replace('\\', '/')
		elif os_vers == 'win32':
			self.filename=filename

		self.NameLen = paquet[38:40]
		self.RootFID = paquet[44:48]
		self.DesiredAccess = paquet[48:52]
		self.Disposition = paquet[68:72]
		self.CreateOption =paquet[72:76]

		logger.info("TID IPC : %i" % glob_tid_IPC )
		if tidcalc(paquet) == string(pack('H', glob_tid_IPC), "ISO-8859-1"):
			self.piped = 1	
		else:
			self.piped = 0

	def calculate(self):
		status = STATUS_SUCCESS
		if self.piped == 1:
			self.fields_SMB_parameter["FileType"]="\x02\x00"
		elif not os.path.exists(self.filename):
			logger.error("**not exist : %s" % self.filename )
			return STATUS_OBJECT_NAME_NOT_FOUND

		global glob_Files
		global glob_FID
		fid = glob_FID
		glob_Files[string(glob_FID)] = [self.filename, self.piped]
		glob_FID = glob_FID + 1
		logger.info("Files tab : %s" % glob_Files )
		self.fields_SMB_parameter["FID"] = string(pack("<H", fid), "ISO-8859-1")
		if self.piped==1:
			return status

		stat=os.lstat(self.filename)
		self.fields_SMB_parameter["Created"] = time_funct(stat[9])
		self.fields_SMB_parameter["LastAccess"] = time_funct(stat[7])
		self.fields_SMB_parameter["LastWrite"] = time_funct(stat[8])
		self.fields_SMB_parameter["Change"] = time_funct(stat[8])
		if(os.path.isdir(self.filename)):
			self.fields_SMB_parameter["FileAttribute"] = "\x10\x00\x00\x00"
			self.fields_SMB_parameter["Directory"] = "\x01\x00"
		else:
			self.fields_SMB_parameter["FileAttribute"] = "\x00\x00\x00\x00"
			self.fields_SMB_parameter["Directory"] = "\x00\x00"

		self.fields_SMB_parameter["EOF"] = pack("<Q", stat[6])
		if os.path.isdir(self.filename):
			self.fields_SMB_parameter["AllocationSize"] = pack("<Q", 0)
		else:
			self.fields_SMB_parameter["AllocationSize"] = pack("<Q", (stat[6] // 4096 + 1 ) * 4096)	
		return status	
	
	def create_p_body(self):
		status = STATUS_SUCCESS
		error = self.calculate()
		if error == STATUS_OBJECT_NAME_NOT_FOUND:
			return reterror(STATUS_OBJECT_NAME_NOT_FOUND)

		for attr in dir(self):
			logger.debug("self.%s : %s" % (attr,getattr(self, attr)) )

		SMB_Param_Data_str = bytes2(self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["AndXCommand"] \
            + self.fields_SMB_parameter["AndXReserved"] + self.fields_SMB_parameter["Andxoffset"] \
				+ self.fields_SMB_parameter["OplockLevel"] + self.fields_SMB_parameter["FID"] \
				+ self.fields_SMB_parameter["CreateAction"], "ISO-8859-1") 
		SMB_Param_Data_str += self.fields_SMB_parameter["Created"] \
				+ self.fields_SMB_parameter["LastAccess"] + self.fields_SMB_parameter["LastWrite"] \
				+ self.fields_SMB_parameter["Change"]
		SMB_Param_Data_str += bytes2(self.fields_SMB_parameter["FileAttribute"], "ISO-8859-1") \
				+ self.fields_SMB_parameter["AllocationSize"] + self.fields_SMB_parameter["EOF"] 
		SMB_Param_Data_str += bytes2(self.fields_SMB_parameter["FileType"] + self.fields_SMB_parameter["IPCstate"] \
				+ self.fields_SMB_parameter["Directory"] + self.fields_SMB_data["Bcc"] + self.fields_SMB_data["Pad1"] \
				+ self.fields_SMB_data["Pad2"] + self.fields_SMB_data["Pad3"], "ISO-8859-1")

		packetBody_bytes=(SMB_Param_Data_str)
		return status, packetBody_bytes, len(SMB_Param_Data_str)

##################################################################################################################
###################################   WriteX Class : write on SMB resource #######################################
##################################################################################################################

class WriteX:
	fields_SMB_parameter = dict([
		("Wordcount",		"\x06"),
		("AndXCommand",	"\xff"),
		("AndXReserved",	"\x00" ),
		("Andxoffset",		"\x00\x00"),
		("Count",			"\x00\x00"),
		("Available",		"\xff\xff"),
		("Reserved",		"\x00\x00\x00\x00"),
	])

	fields_SMB_data = dict([
		("Bcc" ,         "\x00\x00"),
	])

	def __init__(self, data):
		self.FID = unpack("<H", getFID(data))[0]
		offset = unpack("<H",data[55:57])[0]
		self.count = data[53:55]
		self.data = data[offset:]
		logger.info("FID to write : %i" % self.FID) 
		logger.info("Data to write : %s" %  byte2print(self.data))
		logger.info("Count to write : %s (%i)" % (byte2print(self.count),  unpack('H', self.count)[0]))

	def calculate(self):
		if glob_Files[string(self.FID)][1]:
			self.fields_SMB_parameter["Available"]="\x00\x00"

		self.fields_SMB_parameter["Count"]=string(self.count, "ISO-8859-1")

	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()
		SMB_Param_Data_str = self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["AndXCommand"] \
            + self.fields_SMB_parameter["AndXReserved"] + self.fields_SMB_parameter["Andxoffset"] \
				+ self.fields_SMB_parameter["Count"] + self.fields_SMB_parameter["Available"] \
				+ self.fields_SMB_parameter["Reserved"] + self.fields_SMB_data["Bcc"] 

		packetBody_bytes=bytes2((SMB_Param_Data_str), "ISO-8859-1")
		return status, packetBody_bytes, len(SMB_Param_Data_str)

##################################################################################################################
###################################   ReadX Class : read on SMB resource #########################################
##################################################################################################################

class ReadX:
	fields_SMB_parameter = dict([
		("Wordcount",		"\x0c"),
		("AndXCommand",	"\xff"),
		("AndXReserved",	"\x00" ),
		("Andxoffset",		"\x00\x00"),
		("Available",		"\xff\xff"),
		("DataCompactionMode",	"\x00\x00"),
		("Reserved1",		"\x00\x00"),
		("DataLength",		"\x00\x00"),
		("DataOffset",		"\x3b\x00"),
		("Reserved2",		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"),
	])

	fields_SMB_data = dict([
		("BCC" ,         "\x00\x00"),
		("Data" ,         ""),
	])

	def __init__(self, data):
		FID=getFID(data)
		self.FID = unpack("<H", FID)[0]
		logger.info("WC : %i" % data[32] )
		self.WordCount = unpack("B", data[32:33])[0]
		if self.WordCount == 10:
			logger.info("32 bits")
			self.Offset = unpack("<I", data[39:43])[0]
			
		elif self.WordCount == 12:
			logger.info("64 bits")
			self.Offset = unpack("<Q", data[39:43] + data[53:57])[0]

		self.Count = unpack("<H", data[43:45])[0]
		logger.info("FID to read : %i" % self.FID )
		logger.info("WordCount : %i" % self.WordCount )
		logger.info("Offset : %i" % self.Offset )
		logger.info("Count : %i" % self.Count )

	def calculate(self):
		if glob_Files[string(self.FID)][1]:
			self.fields_SMB_parameter["Available"]="\x00\x00"
			self.fields_SMB_parameter["DataLength"]="\x44\x00"
			self.fields_SMB_data["BCC"]=self.fields_SMB_parameter["DataLength"]
			#self.fields_SMB_parameter["DataOffset"]="\x3b\x00"
			# Hardcoded fucking DCERPC
			self.fields_SMB_data["Data"]="\x05\x00\x0c\x03\x10\x00\x00\x00\x44\x00\x00\x00\x02\x00\x00" + \
												  "\x00\xb8\x10\xb8\x10\xf0\x53\x00\x00\x0d\x00\x5c\x50\x49\x50" + \
												  "\x45\x5c\x73\x72\x76\x73\x76\x63\x00\x00\x01\x00\x00\x00\x00" + \
												  "\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00" + \
												  "\x2b\x10\x48\x60\x02\x00\x00\x00"
		else:
			filename =glob_Files[string(self.FID)][0]
			logger.info("File Name : %s" % filename )
			f=open(filename, 'br')
			f.seek(self.Offset)
			data = f.read(self.Count)
			size=len(data)
			self.fields_SMB_parameter["DataLength"]=string(pack("H", size), "ISO-8859-1")
			self.fields_SMB_data["BCC"] = self.fields_SMB_parameter["DataLength"]
			#self.fields_SMB_parameter["DataOffset"]=""
			self.fields_SMB_data["Data"]=string(data, "ISO-8859-1")
			f.close()

	def create_p_body(self):
		status = STATUS_SUCCESS
		self.calculate()
		
		logger.debug("wc %s" % self.fields_SMB_parameter["Wordcount"])
		logger.debug("cmd %s" % self.fields_SMB_parameter["AndXCommand"])
		logger.debug("res %s" % self.fields_SMB_parameter["AndXReserved"])
		logger.debug("offs %s" % self.fields_SMB_parameter["Andxoffset"])
		logger.debug("ava %s" % self.fields_SMB_parameter["Available"])
		logger.debug("compac %s" % self.fields_SMB_parameter["DataCompactionMode"])
		logger.debug("res %s" % self.fields_SMB_parameter["Reserved1"])
		logger.debug("len %s" % self.fields_SMB_parameter["DataLength"])
		logger.debug("offset %s" % self.fields_SMB_parameter["DataOffset"])
		logger.debug("res2 %s" % self.fields_SMB_parameter["Reserved2"])
		logger.debug("bcc %s" % self.fields_SMB_data["BCC"])
		logger.debug("data %s" % self.fields_SMB_data["Data"])


		SMB_Param_Data_str = self.fields_SMB_parameter["Wordcount"] + self.fields_SMB_parameter["AndXCommand"] \
            + self.fields_SMB_parameter["AndXReserved"] + self.fields_SMB_parameter["Andxoffset"] \
				+ self.fields_SMB_parameter["Available"] + self.fields_SMB_parameter["DataCompactionMode"] \
				+ self.fields_SMB_parameter["Reserved1"] + self.fields_SMB_parameter["DataLength"] + \
				self.fields_SMB_parameter["DataOffset"] + self.fields_SMB_parameter["Reserved2"] + \
				self.fields_SMB_data["BCC"] + self.fields_SMB_data["Data"]  

		packetBody_bytes=bytes2((SMB_Param_Data_str), "ISO-8859-1")
		return status, packetBody_bytes, len(SMB_Param_Data_str)

##################################################################################################################
###################################    Socket Parameters   #######################################################
##################################################################################################################

def client(c, debug=None, directory=None):

	global glob_Files
	global glob_FID
	global glob_tid_IPC
	global glob_curdir

	glob_Files = {}
	glob_FID = 13373
	glob_tid_IPC = 0
	glob_curdir = '.'

	# negociation dialect
	NSS = c.recv(4)
	if not NSS:
		exit() 

	global glob_uid
	size = SMBSize(NSS)
	paquet = c.recv(size)      # Receive packet from client
	logger.info("*********************************************************")
	logger.info("Packet received")
	logger.debug("Packet Received : %s", byte2print(paquet))

	h=SMBHeader()
	n=NetBios()
	  
	cmdType=ord(paquet[4:5])
	cmdType2=paquet[33:34]

	if cmdType == 114: 
		h.setmid(midcalc(paquet))
		h.setpid(pidcalc(paquet))
		h.settid(tidcalc(paquet))
		str_h, h_size=h.create_p_header(cmdType)
		logger.info("Request : SMB Negotiate")
		p=SMBNegoAns(paquet)
	else:
		logger.error("**Negotiate error")
		exit()

	errorCode, str_p, b_size=p.create_p_body()
	str_n=n.create_p_NetBios(h_size, b_size) 
	paquet_resp =str_n + str_h + str_p

	c.send(paquet_resp)
	logger.info("Response sent")
	logger.debug("Packet Sent : %s" % byte2print(paquet_resp))

	# nego end

	while True:

		try:
			NSS = c.recv(4)
		except KeyboardInterrupt:
			print ("Interrupt received ...")
			c.close()
			exit()
		if not NSS:
			c.close()
			exit() 

		size = SMBSize(NSS)
		try:
			paquet = c.recv(size)
		except KeyboardInterrupt:
			print ("Interrupt received ...")
			c.close()
			exit()

		logger.info("*********************************************************")
		logger.info("Packet received")
		logger.debug("Packet Received : %s", byte2print(paquet))

		cmdType=ord(paquet[4:5])
		logger.info("Packet command : %i" % cmdType)
		cmdType2=paquet[33:34]
		tid = tidcalc(paquet)
		h.setmid(midcalc(paquet))
		h.settid(tid)
		h.setpid(pidcalc(paquet))

		if cmdType == 115 and cmdType2 == b'\xff':
			logger.info("Request : Session setup andX")
			p=SessSetupAndXAns(paquet)
			if p.moreProcessing():
				h.setpid(pidcalc(paquet))
				h.setuid(string(pack('H', glob_uid), "ISO-8859-1"))
				logger.info("new uid : %s" % glob_uid)
				glob_uid=glob_uid +1
				h.setflags2('\x03\xc8')

		elif cmdType == 117: 
			logger.info("Request : Tree Connect AndX Request")
			p=SMBTreeConnAns(paquet)
			if tid == '\x00\x00':
				h.settid(string(pack('H', glob_tid), "ISO-8859-1"))
		
		elif cmdType == 50:
			logger.info("Request : Trans2 Request")
			#cmd=getSubCmd(paquet)
			p=SMB_Trans2(paquet)

		elif cmdType == 43: 
			logger.info("Request : Echo Request")
			p=SMB_EchoResponse(paquet)

		elif cmdType == 128: 
			logger.info("Request : Query Information Request")
			p=SMB_DiskResponse(paquet)

		elif cmdType == 45: 
			logger.info("Request : Open AndX Request")
			p=SMB_Open_AndX_Ans(paquet)
		
		elif cmdType == 116: 
			logger.info("Request : Logoff AndX Request")
			p=Logoff(paquet)
		
		elif cmdType == 162: 
			logger.info("Request : Create AndX Request")
			p=CreateX(paquet)
		
		elif cmdType == 47:
			logger.info("Request : Write AndX Request")
			p=WriteX(paquet)

		elif cmdType == 46:
			logger.info("Request : Read AndX Request")
			p=ReadX(paquet)

		elif cmdType == 37: 
			logger.info("Request : Trans Request")
			p=SMB_Trans(paquet)

		elif cmdType == 4: 
			logger.info("Request : Close Request")
			p=CloseRequest(paquet)

		elif cmdType == 160:
			logger.info("Request : NT Trans")
			p=NTTrans(paquet)

		elif cmdType == 113: 
			logger.info("Request : Tree Disconnect Request")
			p=TreeDisc(paquet)

		error,str_p, b_size=p.create_p_body()
		h.setErrorCode(error)
		str_h, h_size=h.create_p_header(cmdType)
		h.setErrorCode(STATUS_SUCCESS)
		str_n=n.create_p_NetBios(h_size, b_size)
		paquet_resp =str_n + str_h + str_p
		c.send(paquet_resp)
		logger.info("Response sent")
		logger.debug("Packet Sent : %s" % byte2print(paquet_resp))
		if cmdType == 116:
			print ("Connexion closed")
			break

		"""
		  elif cmdType == b's' and cmdType2 == b'u':
			str_h=h.create_p_header('A')
			p=SessSetupAndX_TreeConn_Ans()

		  elif cmdType == b's' and cmdType2 != b'u': 
				str_h=h.create_p_header('s')
				p=SessSetupAndXAns()

		  ##else :
				## Response par une erreur !! A Completer
		"""
##################################################################################################################
###################################   Start function  ############################################################
##################################################################################################################

def startserver(debug=None, directory=None, filedbg=None):
	global glob_uid
	global glob_curdir

	if filedbg:
		logging.basicConfig(filename='smbresp.log')		
	else:
		logging.basicConfig()

	if debug=='DEBUG':
		logger.setLevel(logging.DEBUG)
	elif debug=='INFO':
		logger.setLevel(logging.INFO)
	elif debug=='WARNING':
		logger.setLevel(logging.WARNING)
	else:
		logger.setLevel(logging.CRITICAL)

	if directory != None:
		if not os.path.exists(directory):
			print ("%s : No such directory" % directory)
			exit()
		else:
			os.chdir(directory)

	s = socket.socket()         # Create a socket object
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	host = '0.0.0.0'
	port = 445                  # Reserve a port
	s.bind((host, port))        # Bind to the port
	s.listen(5)                 # Wait for client connection.
	print ("SMB Server is Running on port 445...")

	while True:
		try:
			c, addr = s.accept()       # Establish connection with client.
		except KeyboardInterrupt:
			print ("Interrupt received ...")
			s.close()
			exit()

		print ("Got connection from", addr)
		glob_uid = glob_uid + 1	
		p = Process(target = client, args =(c,debug, directory))
		p.start()

	s.close()
	c.close()                # Close the connection

##################################################################################################################
###################################################   Main  ######################################################
##################################################################################################################

if __name__ == '__main__':

	parser = OptionParser()
	parser.add_option("-d", "--debug", dest = "debuglvl", help="debug level", metavar="DEBUG|INFO|WARNING")
	parser.add_option("-s", "--share", dest = "directory", help="directory to share", metavar="DIRECTORY")
	parser.add_option("-f", dest = "file", action="store_true", default = False, help="Enable file logging")
	(options, args) = parser.parse_args()

	startserver(options.debuglvl, options.directory, options.file)

