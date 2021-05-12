import re
import sys
from xml.etree import ElementTree 
import os

	
class Extract:

	def __init_(self, page=None, pkts=None, fsms=None, errs=None, key_words=None, key_words_file=None, error_codes=None, state=None, event=None, fields=None, format_key=None, section_file=None, section_meta_file=None):

		self.page = page
		self.pkts = pkts
		self.fsms = fsms
		self.errs = errs
		self.key_words = key_words
		self.key_words_file = key_words_file
		self.error_codes = error_codes
		self.states = states
		self.events = events
		self.fields = fields
		self.format_key = foramt_key
		self.section_file = section_file
		self.section_meta_file = section_meta_file
		

	def xml_find(self, xml, name):
		if xml.find(name) is not None:
			return xml.find(name).text
		else:
			return ""


	def add_key_words(self, word):

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

		section_num = re.findall(r'^\d+\.+', line)
		if section_num:
			return True
		else:
			return False
	# parse packet configure file
	def parse_config_file(self, filename):

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

	def get_struct_section(self, rfc_doc):

		struct_doc = []
		pkt_doc = []
		start_line =["0                   1                   2                   3", "+-----------------------------------------------------+"]
		start_flag = False
		for line in rfc_doc:
			if self.isSectiontitle(line):
				struct_doc.append(line)
				pkt_doc.append(line)
				# print line
				continue
			if line.strip() in start_line:
				# print line
				struct_doc.append(line)
				start_flag = True
				continue
			if line == "\n":
				start_flag = False
			if start_flag:
				struct_doc.append(line)
			else:
				pkt_doc.append(line)
				# print line
	

		return struct_doc, pkt_doc

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

				section_name = "4.  Message Formats"
				next_section = "5.  Path Attributes"
				# section_meta_name = "4.5.  NOTIFICATION Message Format"
				# next_section_meta = "5.  Path Attributes"
				rule_doc = self.splict_doc(lines, section_name, next_section)

				struct_doc, pkt_doc = self.get_struct_section(rule_doc)

				# print pkt_doc
				self.write_in_doc(pkt_doc, self.section_file)
				self.write_in_doc(struct_doc, self.section_meta_file)

			else:
				print "[WARN] Please give the rfc document in <sectoin_file>."
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
				print "[WARN] Please give the rfc document in <sectoin_file>."
				sys.exit()
	

if __name__ == '__main__':

	pass

