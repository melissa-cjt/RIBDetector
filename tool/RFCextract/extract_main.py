import re
import sys
from xml.etree import ElementTree 
import os
import json

	
class Extract(object):

	def __init__(self):

		self.page = None
		self.pkts = None
		self.fsms = None
		self.errs = None
		self.key_words = None
		self.key_words_file = None
		self.error_codes = None
		self.states = None
		self.events = None
		self.fields = None
		self.format_key = None
		self.section_file = None
		self.section_meta_file = None
		self.section_file_error = None
		self.section_meta_file_error = None
		self.section_file_fsm = None
		self.section_meta_file_fsm = None
		self.pkt_ftype =None   # the description method of the RFC packet rules
		self.pkt_pos = None # 0: no pkt format, 1: figure, 2: asn ,3: struct 
		self.json_data ={}
		self.err_code = {}
		self.err_subcode = {}
		self.err_code_name = []
		self.pkt_rul = {}
		self.meta_rul = {}

	def xml_find(self, xml, name):
		if xml.find(name) is not None:
			return xml.find(name).text
		else:
			return ""

	def add_key_words_list(self, key_list):

		for key in key_list:
			self.add_key_words(key)
	def add_key_words(self, word):

		if "0x" in word:
			w = word.strip("0x")
			if w.isdigit():
				return
		if word.isdigit():
			return
		if word =="...":
			return
		word = word.strip("#").strip()

		if word not in self.key_words:
			self.key_words.append(word)

	def read_key_words(self, file):

		f = open(file, "r")
		k = f.read()
		self.key_words = eval(k)
		f.close()

	def get_section_title(self, line):

		section_num = re.findall(r'\w+\.+',line)
		if section_num:

			section_num = "".join(section_num)
			# print section_num
			section_name = line.replace(section_num, "").strip()
			# print section_name
		else:
			return ""

		return section_name

	def isSectiontitle(self, line):

		section_num = re.findall(r'^\w+\.+', line)
		if section_num:
			return True
		else:
			return False
	def parse_config_file_json(self, filename):

		with open(filename, 'r') as f:
			self.json_data = json.load(f)
	

		self.page = self.json_data["page"]
		# print(self.page) 

		if "key_word_file" in self.json_data.keys():
			self.key_words_file = self.json_data["key_word_file"]
			self.read_key_words(self.key_words_file)
		else:
			self.key_words=[]
		# self.key_words_file = self.json_data["key_word"]
		# pass
		# self.key_words = self.xml_find(root, "key_words")

		if "key_words" in self.json_data.keys():

			kws = self.json_data["key_words"]
		
			for kw in kws:
				
				self.add_key_words(kw)
		else:
			self.key_words=[]
		
		self.error_codes = {}
		self.states = []
		self.events = []
		self.fields = {}


	# parse packet configure file
	def parse_config_file(self, filename):
		# print "ok"

		root = ElementTree.parse(filename)

		self.page = root.findall("page")[0].text
		self.pkts = root.findall("packet_format")
		self.fsms = root.findall("fsm")
		self.errs = root.findall("error_handling")

		self.key_words_file = self.xml_find(root, "key_words_file")

        
		if self.key_words_file:

			self.read_key_words(self.key_words_file)
		else:

			self.key_words=[]


		self.key_words = self.xml_find(root, "key_words")

		if self.key_words:

			kws = root.findall("key_words")[0]
		
			for kw in kws:
				
				self.add_key_words(kw.text)
		else:
			self.key_words=[]
		
		self.error_codes = {}
		self.states = []
		self.events = []
		self.fields = {}


	def clear_space(self, lines):

		for i in range(0, len(lines)):

			if lines[i] == "\n":
				continue

			if "\n" in lines[i]:
				lines[i]=lines[i].rstrip()


	def write_key_words(self, filename):

		f = open("tmp/kw_"+filename.split("/")[-1],'w')
		f.write(str(self.key_words))
		f.close()

	def splict_doc(self, rfc_doc, section, next_section):

		for i in range(0, len(rfc_doc)):
			if section in rfc_doc[i]:
				start = i
				# print "start from:"+str(start)
	
			if next_section in rfc_doc[i]:
				stop = i
				# print "end of:"+str(stop)

			if self.page in rfc_doc[i]:
				for num in range(-5,3):
					rfc_doc[i+num] = "DEL LINE\n"

		rfc_section = rfc_doc[start : stop]
		return rfc_section	


	def write_in_doc(self, tmp_doc, filename):
		f = open(filename, "w")
		for l in tmp_doc:
			if "DEL LINE" in l:
				continue
			# if l == "\n":
			# 	f.write(l)
			# if "\n" in l:
			# 	l=l.rstrip()

			f.write(l)
		f.close()


	# split the sentence and the gragh from the documents
	def get_struct_section(self, rfc_doc):

		struct_doc = []
		pkt_doc = []
		start_line =["0                   1                   2                   3", "+-----------------------------------------------------+"]
		struct_line=["struct {","enum {"]
		start_flag = False
		for line in rfc_doc:
			if self.isSectiontitle(line):
				struct_doc.append(line)
				pkt_doc.append(line)
				# print line
				continue
			if self.pkt_pos <=1:
				if line.strip() in start_line:
					# print line
					struct_doc.append(line)
					start_flag = True
					continue
			elif self.pkt_pos == 2:
				if " ::=" in line:
					struct_doc.append(line)
					start_flag = True
					continue
			elif self.pkt_pos == 3:
				for stc in struct_line:
					if stc in line:
						start_flag = True
						# struct_doc.append(line)
						continue
			elif self.pkt_pos == 4:
				if "+-----+-----+" in line.strip():
					struct_doc.append(line)
					start_flag = True
					continue
			if line == "\n":
				# struct_doc.append(line)
				start_flag = False

			if start_flag:
				struct_doc.append(line)
			else:
				pkt_doc.append(line)
				# print line
	
		for i in range(0, len(struct_doc)-1):
			if self.isSectiontitle(struct_doc[i]) and self.isSectiontitle(struct_doc[i+1]):
				struct_doc[i]=""
		if self.isSectiontitle(struct_doc[-1]):
			struct_doc[-1]=""
		return struct_doc, pkt_doc

	def packet_json_nw(self):

		self.section_file = self.json_data["filename"]
		self.pkt_ftype =self.json_data["packet_format"]["pkt_field_in_para"]
		self.pkt_pos = self.json_data["packet_format"]["pkt_fmt_is_graph"]


		if "file" in self.json_data["packet_format"].keys():
			self.section_meta_file = self.json_data["packet_format"]["file"]["meta"]
			self.section_file = self.json_data["packet_format"]["file"]["rule"]
		else:
	
			f = open(self.section_file, "r")
			lines = f.readlines()
			f.close()

			isExists = os.path.exists("tmp")
			if not isExists:
				os.makedirs("tmp")

			self.section_meta_file = "tmp/pktmeta_"+self.section_file.split("/")[-1]
			self.section_file = "tmp/pktrule_"+self.section_file.split("/")[-1]
			noused_file = "tmp/nusued_"+self.section_file.split("/")[-1]

			section_name = self.json_data["packet_format"]["section_start"]
			next_section = self.json_data["packet_format"]["section_end"]
			self.noused_figure = self.json_data["packet_format"]["noused_figure"]

			noused_line = []

			for fig in self.noused_figure:
				begin = fig[0]-1
				end = fig[1]-1
				for i in range(begin, end+1):
					noused_line.append(lines[i])
					lines[i]=""
					
			
			rule_doc = self.splict_doc(lines, section_name, next_section)
		
			struct_doc, pkt_doc = self.get_struct_section(rule_doc)

			self.write_in_doc(pkt_doc, self.section_file)
			self.write_in_doc(struct_doc, self.section_meta_file)
			self.write_in_doc(noused_line, noused_file )

	def packet_nw(self):
		for pkt in self.pkts:
			if self.xml_find(pkt, "section_file"):
				self.section_file = pkt.find("section_file").text
				# print self.section_file
				f = open(self.section_file, "r")
				lines = f.readlines()
				f.close()

				isExists = os.path.exists("tmp")
				if not isExists:
					os.makedirs("tmp")

				self.section_meta_file = "tmp/pktmeta_"+self.section_file.split("/")[-1]
				self.section_file = "tmp/pktrule_"+self.section_file.split("/")[-1]

				# print self.section_meta_file
				# print self.section_file
				if self.xml_find(pkt, "section_start"):
					section_name = pkt.find("section_start").text
				if self.xml_find(pkt, "section_end"):
					next_section = pkt.find("section_end").text

				if self.xml_find(pkt, "pkt_format_type"):
					self.pkt_ftype = pkt.find("pkt_format_type").text

				# section_name = "4.  Message Formats"
				# next_section = "5.  Path Attributes"
				# section_meta_name = "4.5.  NOTIFICATION Message Format"
				# next_section_meta = "5.  Path Attributes"
				rule_doc = self.splict_doc(lines, section_name, next_section)
				# if(self.pkt_pos == 1)
				struct_doc, pkt_doc = self.get_struct_section(rule_doc)

				# print pkt_doc
				self.write_in_doc(pkt_doc, self.section_file)
				self.write_in_doc(struct_doc, self.section_meta_file)

			else:
				print("[WARN] Please give the rfc document in <sectoin_file>.") 
				sys.exit()


	def err_handling_nw(self):	

		for err in self.errs:

			if self.xml_find(err, "section_file"):
				self.section_file = err.find("section_file").text
				
				f = open(self.section_file, "r")
				lines = f.readlines()
				f.close()
				
				isExists = os.path.exists("tmp")
				if not isExists:
					os.makedirs("tmp")

				self.section_meta_file = "tmp/errmeta_"+self.section_file.split("/")[-1]
				self.section_file = "tmp/errrule_"+self.section_file.split("/")[-1]

				# print self.section_meta_file
				# print self.section_file

				section_name = "6.1.  Message Header Error Handling"
				next_section = "6.4.  NOTIFICATION Message Error Handling"
				section_meta_name = "4.5.  NOTIFICATION Message Format"
				next_section_meta = "5.  Path Attributes"

				rule_doc = self.splict_doc(lines, section_name, next_section)
				meta_doc = self.splict_doc(lines, section_meta_name, next_section_meta)
					
				self.write_in_doc(rule_doc, self.section_file)
				self.write_in_doc(meta_doc, self.section_meta_file)		
					

			else:
				print("[WARN] Please give the rfc document in <sectoin_file>.")
				sys.exit()

	def err_handling_json_nw(self, meta_file):

		# print(self.section_file)
		# print(self.json_data)
		self.section_file = meta_file

		self.section_file_error = self.json_data["filename"]
		# self.section_file = self.json_data["filename"]

		if "file" in self.json_data["Error_Handling"]:
			self.section_file_error = self.json_data["Error_Handling"]["file"]["rule"]
		else:
			f = open(self.section_file_error, "r")
			lines = f.readlines()
			f.close()

			isExists = os.path.exists("tmp")
			if not isExists:
				os.makedirs("tmp")
			self.section_file_error = "tmp/errrule_"+self.section_file_error.split("/")[-1]

			section_name = self.json_data["Error_Handling"]["section_start"]
			next_section = self.json_data["Error_Handling"]["section_end"]
			rule_doc = self.splict_doc(lines, section_name, next_section)

			self.write_in_doc(rule_doc, self.section_file_error)
		self.get_error_code()
		
	def get_error_code(self):
		# print(self.section_file)
		
		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
			json_tmp  = json.load(f)
		# print(json_tmp)
		self.meta_rul = json_tmp
		err_meta = self.json_data["Error_Handling"]["Error_code_meta"]["error_code"]

		for err in err_meta:
			self.err_code = json_tmp["Value_list"][err]
			self.err_code_name += json_tmp["Value_list"][err].keys()
		err_smeta = self.json_data["Error_Handling"]["Error_code_meta"]["error_subcode"]

		for errs in err_smeta:
			self.err_subcode[errs]= json_tmp["Value_list"][errs]
			self.err_code_name += json_tmp["Value_list"][errs].keys()
		# print(self.err_code)
		# print(self.err_subcode)

	def fsm_json(self, meta_file):
		self.section_file = meta_file
		self.section_file_fsm = self.json_data["filename"]

		if "file" in self.json_data["FSM"]:
			self.section_file_fsm = self.json_data["FSM"]["file"]["rule"]
		else:
			f = open(self.section_file_fsm, "r")
			lines = f.readlines()
			f.close()

			isExists = os.path.exists("tmp")
			if not isExists:
				os.makedirs("tmp")
			self.section_file_fsm = "tmp/fsmrule_"+self.section_file_fsm.split("/")[-1]

			section_name = self.json_data["FSM"]["section_start"]
			next_section = self.json_data["FSM"]["section_end"]
			rule_doc = self.splict_doc(lines, section_name, next_section)

			self.write_in_doc(rule_doc, self.section_file_fsm)




if __name__ == '__main__':

	pass

