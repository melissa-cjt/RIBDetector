import re
import sys
from xml.etree import ElementTree 
import os
from extract_main import Extract
from extract_rfc_rules import RFC_Extract
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString
import copy
from collections import OrderedDict
import json
from time import *

class RFC_PKT_Rules_Extract(Extract, RFC_Extract):


	def __init_(self):

		# super().__init_(page=None, pkts=None, fsms=None, errs=None, key_words=None, error_codes=None, state=None, event=None, fields=None, format_key=None, section_file=None, pkt_temp=None, fieldname_left=None, fieldname_right= None, rules_left=None, rules_right=None)
		super().__init_(page=None, pkts=None, fsms=None, errs=None, key_words=None, error_codes=None, state=None, event=None, fields=None, format_key=None, section_file=None)

		self.pkt_temp = pkt_temp
		self.fieldname_left=fieldname_left
		self.fieldname_right = fieldname_right
		self.rules_right = rules_right
		self.rules_left = rules_left
		self.max_line = max_line
		self.field_has_rule = field_has_rule
		self.bw_file = bw_file
		self.field_bw_list = field_bw_list
		self.struct_configure = struct_configure
		self.Rules= Rules
		
		# self.filedname_section={}
		
	def isfieldname(self, line):
		pass

		
	def split_field_section(self):

		f = open(self.section_file,"r")
		lines = f.readlines()
		f.close()
		# print self.key_words
		# print self.field_bw_list

		message_field = []
		field_regx = ""

		field_section = {}
		fflag = False

		oldspace = 0
		space =0

		start_line = ["0                   1", "+---------------------------+"]
		struct_list = {}
		start_flag = False

		oldname = "SECTION_RULES"
		for line in lines:
			pline = line.strip()
			# print pline

			space = len(line) -len(pline)

			if self.isSectiontitle(line):
				section_name = self.get_section_title(pline)
				
				if not section_name:
					continue

				# print section_name
				message_field= self.field_bw_list[section_name].keys()
				# print message_field
				field_section[section_name]={}
				field_section[section_name]["SECTION_RULES"] = []
				fflag = False
				continue
			# print "ok"
			# print line
			if pline.rstrip(':') in message_field:
				# print line
				fieldname = pline.rstrip(':')

				field_regx = pline.replace(fieldname, "(.*)")
				# print field_regx
				# print fieldname
				
				field_section[section_name][fieldname]=[]
				struct_list[fieldname] = []
				fflag = True
				oldspace = space
				continue

			if pline in start_line:
				# print pline
				struct_list[fieldname].append(line)
				start_flag = True
				continue


			if start_flag:

				if line == "\n":
					start_flag = False

				struct_list[fieldname].append(line)
				
			else:
				# pass
				if line == "\n":
					continue
				# fflag = True
				if fflag:
					
					if oldspace <= space:
						# print pline
						field_section[section_name][fieldname].append(pline)
						# oldname = fieldname
						
					else:
						field_section[section_name]["SECTION_RULES"].append(pline)
					
						fflag = False
				else:
					field_section[section_name]["SECTION_RULES"].append(pline)
		
		return field_section, struct_list

	def get_pkt_meta(self, sen):

		meta = {}
		nw_sen = []

		for s in sen:
			if re.findall(r'^\d+ - \w+', s):
				res = re.findall(r'^(\d+) - (.*)', s)
				meta_name = res[0][1]
				meta_id= res[0][0]
				# print meta_name , meta_id
				meta[meta_name]= meta_id
			elif re.findall(r'(\d+)         (.*)    (.*)', s):
				res = re.findall(r'(\d+)         (.*)    (.*)', s)
				meta_name = res[0][1]
				meta_id = res[0][0]

				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)         (.*) - (.*)', s):
				res = re.findall(r'(\d+)         (.*) - (.*)', s)
				meta_name = res[0][1]
				meta_id = res[0][0]

				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)         (.*): (.*)', s):
				res = re.findall(r'(\d+)         (.*): (.*)', s)
				meta_name = res[0][1]
				meta_id = res[0][0]

				meta[meta_name] = meta_id
			
			else:
				nw_sen.append(s)

		# print meta
		return copy.deepcopy(meta), nw_sen

	def find_subfield(self, section_field):

		print "Find sub field  ==============="
		start_line = ["0                   1","+---------------------------+"]
		struct_list = []
		start_flag = False

		for sec, field in section_field.items():

			# print sec

			for fname, sents in field.items():
			

				for sent in sents:

					if sent.strip() in start_line:
					
						struct_list.append(sent)
						start_flag = True
						continue
					if sent == "":
						start_flag = False
					
					if start_flag:
						struct_list.append(sent)
					
			struct_list=[]	

	def get_subfname(self, sen, fn):

		meta={}
		flag = False
		rules ={}
		rules[fn] =[]

		for s in sen:
			if re.findall(r'(\w+)\) (.*) \(Type Code (.*)\)', s):
				res = re.findall(r'(\w+)\) (.*) \(Type Code (.*)\)', s)
				meta_name = res[0][1]
				meta_id = res[0][2]
				meta[meta_name] = meta_id
				rules[meta_name]=[]
				flag = True

			else:
				if not flag:
					rules[fn].append(s)
				else:
					rules[meta_name].append(s)
		return rules, meta, flag

			
	def pkt_format_rule(self):
		
		field_section, struct_list = self.split_field_section()
		# print field_section
		pkt_rules={}

		for sec, fname in field_section.items():
			
			pkt_rules[sec]={}
			
			for fn, sen in fname.items():
				# print fn, "==="
				pkt_rules[sec][fn]={}

				subsen, submeta, subflag = self.get_subfname(sen, fn)

				if subflag:
					# print submeta
					for subn, subs in subsen.items():
						pkt_rules[sec][subn]={}
						# print subn 
					
						meta, nw_sen = self.get_pkt_meta(subs)
						s =self.pre_process_rules_nw(nw_sen, fn, True)
						# print s 
						rules = self.get_common_rules_nw(s, False)
						# print rules
						if subn not in self.field_bw_list[sec].keys():
							self.add_key_words(subn)
							
							self.field_bw_list[sec][subn] = self.get_sent_bitwidth(" ".join(s))

						pkt_rules[sec][subn]["rules"]=rules
						pkt_rules[sec][subn]["meta"]= meta
					pkt_rules[sec][fn]["meta"] = submeta
				else:

					meta, nw_sen = self.get_pkt_meta(sen)
					
					s =self.pre_process_rules_nw(nw_sen, fn, True)

					rules = self.get_common_rules_nw(s, False)

					pkt_rules[sec][fn]["rules"]=rules
					pkt_rules[sec][fn]["meta"]= meta
	
		self.write_in_json(pkt_rules)
		self.write_meta_in_json(pkt_rules)

	def write_in_json(self, err_rules):
		
		rule ={}
		self.Rules={}
		self.Rules["PacketField"]=[]
		meta_rule={
			"lhs":"x",
			"predicate": 32,
			"rhs":""

		}
		rfc_rule={
			"rfc_cond":[],
			"keyword": "",
			"type":1,
			"connect":[]
		}

		for sec, field in err_rules.items():
			# print sec
			for fn, rul in field.items():
				if fn == "SECTION_RULES":
					rule["FieldName"] = "SEC "+sec.replace(" Format","")

				else:
					rule["FieldName"]=fn
					rule["BitWidth"]=self.field_bw_list[sec][fn]
				rule["rfc_conds"]=rul["rules"]
				

				if rul["meta"]:
					# print rul["meta"]
					rfc_rule["keyword"]=fn+" type"
					for k, v in rul["meta"].items():
						meta_rule["rhs"] = v
						rfc_rule["rfc_cond"].append(copy.deepcopy(meta_rule))
						rfc_rule["connect"].append(2)
					# rule["type"] = 3
					rfc_rule["type"] = 3
					rule["rfc_conds"].append(copy.deepcopy(rfc_rule))
					rfc_rule["rfc_cond"]=[]
					rfc_rule["connect"] = []
					rfc_rule["type"] =1
					

				self.Rules["PacketField"].append(copy.deepcopy(rule))
				rule={}
		isExists = os.path.exists("../output/tmp")
		if not isExists:
			os.makedirs("../output/tmp")
		with open("../output/tmp/rule-pkt.json",'w') as f:
			json.dump(self.Rules, f, indent=4)

	def write_meta_in_json(self, rules):

		meta_infos = []

		meta_info={ 
			"FieldName": "",
			"meta_info": {}
			}

		for sec, field in rules.items():
			# print sec
			for fn, rul in field.items():
				meta_info["FieldName"] = fn
				if rul["meta"]:
					meta_info["meta_info"] = rul["meta"]

					meta_infos.append(copy.deepcopy(meta_info))

		# isExists = os.path.exists("../output/tmp")
		# if not isExists:
		# 	os.makedirs("../output/tmp")

		# with open("../output/tmp/meta-info-pkt-f.json",'w') as f:
		# 	json.dump(meta_infos, f, indent=4)

	def pkt_format_templete(self):

		for pkt in self.pkts:

			if pkt.find("bw_file") is not None:

				self.bw_file = pkt.find("bw_file").text

				self.get_picture_bw()

			if pkt.find("section") is not None:
				pass

			elif pkt.find("section_file") is not None:


				self.section_file = pkt.find("section_file").text

				self.pkt_temp = pkt.find("template").text
				#print self.pkt_temp

				if self.pkt_temp == "A":

					section = self.template_A_parse(pkt)
					# bitwidth, common_rules = self.get_pkt_rules(section)

					rules = self.get_pkt_rules(section)
					self.write_in_xml(rules)

					self.write_key_words(self.section_file)

				elif self.pkt_temp == "B":
					section = self.template_B_parse(pkt)
					
					rules = self.get_pkt_rules(section)
					self.write_in_xml(rules)

					self.write_key_words(self.section_file)
					# self.pkt_temp = pkt.find("template_B")
					pass

			else:
				print "ERROR: Please offer the rfc document for analysis!"
				sys.exit()



	def get_field_bw(self, bw):

		bw_len = (len(bw)+1)/2
		bw_name = bw.strip()

		if "(variable" in bw_name or "(Variable" in bw_name:
			bw_len = 0
			bw_name = re.sub(r'\((.*)\)','', bw_name)
			bw_name = bw_name.strip()
		elif "(see " in bw_name:
			bw_name = re.sub(r'\((.*)\)','', bw_name)
			bw_name = bw_name.strip()
		elif re.findall(r'\((.*) octets\)', bw_name):
			bw_len = re.findall(r'\((.*) octets\)', bw_name)
			# print bw_len
			bw_len = int(bw_len[0])*8
			bw_name = re.sub(r'\((.*)\)','', bw_name)
			bw_name = bw_name.strip()

		# bw_name= bw_name.strip()
		return bw_len, bw_name
		

	def get_field_length(self, bw_list, flag, name):

		field_bw = OrderedDict()
		bw_len = 0
		bw_name = ""

		if len(bw_list) == 1:
			bw = bw_list[0]
			if "|" in bw:
				bw_temp = bw.split("|")
				# print bw_temp
				for b in bw_temp:
					bw_len , bw_name = self.get_field_bw(b)
					if flag:
						bw_name = name
						flag= False
					field_bw[bw_name] = bw_len
					# print bw_len, bw_name
			else:
				bw_len, bw_name = self.get_field_bw(bw)
				if flag:
					bw_name = name 
				field_bw[bw_name] = bw_len
				# print bw_len, bw_name
		else:
			for bw in bw_list:

				if bw.isspace():
					len_temp , space = self.get_field_bw(bw)
					bw_len = bw_len+len_temp
				else:
					len_temp, name_temp = self.get_field_bw(bw)
					bw_name = bw_name + name_temp+" "

					if len_temp == 0:
						bw_len = 0
						break
					elif len_temp != 32:
						bw_len = len_temp
						break
					else:
						bw_len = bw_len + len_temp						
			if flag:
				bw_name = name
			# print bw_len, bw_name
			field_bw[bw_name.strip()] = bw_len
			
		return field_bw		


	def get_picture_bw_nw(self):

		f = open(self.section_meta_file, "r")
		lines = f.readlines()
		f.close()

		pkt_bw={}

		field_res = ""
		field_bw =[]

		self.field_bw_list=OrderedDict()
		bw_name_flag = False
		bw_len_flag = False
		space_flag = False
		bw_name = ""

		self.struct_configure={
			"predict_type":"Struct",
			"Dir":"NONE",
			"varibale_range":-1,
			"Struct_list":[]
		}
		

		print "GET PACKET FIELD BITWIDTH "

		for i in range(len(lines)):
			line = lines[i].strip()
			# print line

			if re.match(r'\w+\.+', line):
				# print "section"

				section_name = self.get_section_title(line)

				# field_bw_list[section_name] = {}
				self.field_bw_list[section_name] = OrderedDict()
				field_bw = []
				bw_old_temp=OrderedDict()
				# print section_name
			elif "+-  " in line:
				# print "+-    -+ type"

				tmp_name = re.findall(r'\+\- (.*) \-\+', line)

				if not tmp_name[0].isspace():
					bw_name = tmp_name[0].strip()
					bw_name_flag = True

			elif "+-+-+-+-+-+-+-+-+" in line or "+--------" in line or "+--+--+--+--+--+" in line:
					# print field_res
				if field_res:
					

					# print field_bw
					bw_temp = self.get_field_length(field_bw, bw_name_flag, bw_name)
					# print bw_temp
					bw_name_flag = False
					bw_name = ""
					# print bw_temp

					if bw_len_flag:

						last = bw_temp.keys()[-1]
						bw_temp[last]=0
						bw_len_flag =False


					for k , v in bw_temp.items():

						if k in bw_old_temp.keys():
							if self.field_bw_list[section_name][k] != 0:
								self.field_bw_list[section_name][k] +=v
						else:
							if k != '':
								self.field_bw_list[section_name][k] = v
							else:
								if "        +" in lines[i-2].strip():
									last_name = self.field_bw_list[section_name].keys()[-1]
									if self.field_bw_list[section_name][last_name] != 0:
										self.field_bw_list[section_name][last_name]+=v
								if "      |" in lines[i].strip():
									tmp_name = re.findall(r'\+ (.*) \|', line)
									if not tmp_name[0].isspace():
										bw_name = tmp_name[0].strip()
										bw_name_flag = True
										self.field_bw_list[section_name][bw_name] = v
										space_flag = True

					
					field_bw=[]

					
					bw_old_temp = copy.copy(bw_temp)

					if space_flag:
						bw_old_temp[bw_name] = bw_temp.pop('')
						space_flag = False
				
				# else:
				# 	print "START "+section_name


			elif "~    " in line:
				
				bw_len_flag = True
			# elif ""
			else:

		
				field_res = re.findall(r'\|(.*)\|', line)
				# print field_res
				if field_res:
					# print field_res
					field_bw = field_bw + copy.copy(field_res)
		
		
		for k, v in self.field_bw_list.items():
			tmp_str = {}
			if not v:
				continue 
			tmp_str["struct_name"]=k
			tmp_str["value"]=[]

			for kk, vv in v.items():
				tmp_str["value"].append(vv)
				self.add_key_words(kk)
			self.struct_configure["Struct_list"].append(tmp_str)

		# isExists = os.path.exists("../output/tmp")
		# if not isExists:
		# 	os.makedirs("../output/tmp")

		# with open("../output/tmp/meta-info-pkt-s.json",'w') as f:
		# 	json.dump(self.struct_configure, f,indent=4)
		print "==========================="

	def get_sent_bitwidth(self, sents):
		# print "get bitwidth"
		# print sents
		sents = sents.replace("KW_Length", "length")

		if "-octet" in sents:
			n = sents.index("-octet")
			sub = sents[:n]
			bitwidth = sub.split(" ")[-1]
			if bitwidth.isdigit():
				bitwidth = int(bitwidth)*8
			elif bitwidth in self.word2num.keys():
				bitwidth = self.word2num[bitwidth]*8
		elif " octet " in sents:
			# print "in oct"
			# print sents
			bitwidth = sents.split(" octet")
			bitwidth = bitwidth[0].split(" ")[-1]
			if bitwidth.isdigit():
				# print 1
				bitwidth = int(bitwidth)*8
			elif bitwidth in self.word2num.keys():
				# print 2
				bitwidth = self.word2num[bitwidth]*8
			else:
				# print 3
				bitwidth = 0
			# print bitwidth
		elif "-bit value" in sents:
			bitwidth = sents.split("-bit value")
			bitwidth = bitwidth[0].split(" ")[-1]
		elif re.findall(r'(.*) of length (\d+)', sents):
			bits = re.findall(r'(.*) of length (\d+)', sents)
			# print bits
			bitwidth = int(bits[0][1])*8
		else:
			bitwidth = 0
		# print bitwidth
		return bitwidth
	def get_bitwidth(self, sec, fn, sents):

		if sec in self.field_bw_list.keys():
			if fn in self.field_bw_list[sec].keys():
				# print "ok"

				bitwidth = self.field_bw_list[sec][fn]
				return str(bitwidth)
			else:

				if "#" in fn:
					fn = fn.replace("#","")
					fn = fn.strip()
				if "bit " in fn:
					# print "ok"
					fn = fn.replace("bit ","")
					fn = fn.strip()
					# print fn
				if "-bit" in fn:
					fn = fn.replace("-bit","")
					fn = fn.strip()

				for k in self.field_bw_list[sec].keys():
					if fn.lower() == k.lower():
						fn = k
						break
					if "#" in k:
						tmp_k = k.replace("#","")
						tmp_k = tmp_k.strip()
						if fn == tmp_k:
							fn = k
							break
					if "(0x" in k:
						tmp_k = re.sub(r'\((.*)\)','', k)
						tmp_k = tmp_k.strip()
						if fn == tmp_k:
							fn = k
							break
					if "...." in k:
						tmp_k = k.replace("....","")
						tmp_k = tmp_k.strip()
						if fn == tmp_k:
							fn = k
							break

				if fn in self.field_bw_list[sec].keys():
					# print fn
					bitwidth = self.field_bw_list[sec][fn]
					return str(bitwidth)
					# print bitwidth

		bitwidth = self.get_sent_bitwidth(sents)
		return bitwidth



if __name__ == '__main__':

	pass