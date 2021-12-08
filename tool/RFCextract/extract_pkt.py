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
import nltk
import spacy
import logging

class RFC_PKT_Rules_Extract(Extract, RFC_Extract):


	def __init__(self):

		super(RFC_PKT_Rules_Extract, self).__init__()
		RFC_Extract.__init__(self)

		self.pkt_temp = None
		self.fieldname_left=None
		self.fieldname_right = None
		self.rules_right = None
		self.rules_left = None
		self.max_line = None
		self.field_has_rule = None
		self.bw_file = None
		self.opt_bw = {}
		self.field_bw_list=OrderedDict()
		self.mt_if ={}
		self.struct_configure = {}
		self.struct_expansion = {}
		self.Rules= {}
		
		# self.filedname_section={}
		
	def isfieldname(self, line):
		pass

		
	def split_field_section(self, nlp):

		f = open(self.section_file,"r")
		lines = f.readlines()
		f.close()
		# print self.key_words
		# print self.field_bw_list

		message_field = []
		field_regx = ""

		field_section = OrderedDict()
		fflag = False

		oldspace = 0
		space =0

		start_line = ["0                   1", "+---------------------------+"]
		struct_list = {}
		start_flag = False

		rf = self.json_data["packet_format"]["format"]["rfield"]

		iswrap = self.json_data["packet_format"]["format"]["iswrap"]
		# print("iswrap:", iswrap)

		oldname = "SECTION_RULES"
		for line in lines:
			pline = line.strip()
			# print pline
			# print("-------")
			# print(pline)
			if line != "\n":

				space = len(line) -len(pline)
				# print(space)

			if self.isSectiontitle(line):
				section_name = self.get_section_title(pline)
				
				if not section_name:
					continue
				if section_name in self.field_bw_list.keys():
				# print section_name
					message_field= self.field_bw_list[section_name].keys()
				# print(message_field)
				field_section[section_name]={}
				field_section[section_name]["SECTION_RULES"] = []
				fflag = False
				continue
			# print "ok"
			# print line
			if not iswrap:

				tmpline = pline.split(rf)
				# print(tmpline)
				if tmpline[0] in message_field:
					fieldname = tmpline[0]
					field_section[section_name][fieldname]=[]
					field_section[section_name][fieldname].append(tmpline[1])
					struct_list[fieldname] = []
					fflag = True
					oldspace = space
					continue


			elif pline.rstrip(rf) in message_field:
				# print(line +"------------------")
				# print("is rstrip field")
				fieldname = pline.rstrip(rf)

				field_regx = pline.replace(fieldname, "(.*)")
				# print field_regx
				# print fieldname
				
				field_section[section_name][fieldname]=[]
				struct_list[fieldname] = []
				fflag = True
				oldspace = space
				continue
			elif pline.endswith(rf):
				# print("========")

				# print("is endswith")

				if self.isfixedValuetitle(pline):
					continue
				
				tmp = pline.rstrip(rf)
				# print("sss")
				# if ")" in tmp:
				# 	continue
				# print(tmp)
				doc = nlp(tmp)
				isother = False

				if not self.isPktMeta(tmp):

				# print(len(doc.noun_chunks))
					for chunk in doc.noun_chunks:
						# print("chunk")
						if chunk.text == tmp:
							if ")" in tmp:
								break
							# print(chunk.text, tmp)

							fieldname = tmp
							field_section[section_name][fieldname]=[]
							struct_list[fieldname] = []
							fflag = True
							isother = True
							oldspace = space
				if isother:
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
						# print(pline)
						field_section[section_name][fieldname].append(pline)
						# oldname = fieldname
						# print("in field", oldspace)
						
					else:
						field_section[section_name]["SECTION_RULES"].append(pline)
						# print("in section", oldspace)
					
						fflag = False
				else:
					field_section[section_name]["SECTION_RULES"].append(pline)
					# print("in section", oldspace)
		
		return field_section, struct_list

	def get_pkt_meta(self, sen):

		meta = {}
		nw_sen = []
		title =["Type   Description","________________________________","LS Type   Description","Type   Link ID"]

		for s in sen:
			if re.findall(r'^\d+ - \w+', s):
				res = re.findall(r'^(\d+) - (.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id= res[0][0]
				# print meta_name , meta_id
				meta[meta_name]= meta_id
			elif re.findall(r'(\w+) - (\d+)', s):
				res = re.findall(r'(\w+) - (\d+)', s)
				meta_name = res[0][0].strip().replace(".","")
				meta_id= res[0][1]
				# print meta_name , meta_id
				meta[meta_name]= meta_id
			elif re.findall(r'(\d+)      (.*)  Section(.*)', s):
				res = re.findall(r'(\d+)      (.*)  Section(.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)      (.*)', s):
				res = re.findall(r'(\d+)      (.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			elif re.findall(r'(\w+)(.*) 0x(\d+)(.*)  (\d+)', s):
				res = re.findall(r'(\w+)(.*) 0x(\d+)(.*)  (\d+)', s)
				meta_name = res[0][0].strip().replace(".","")
				meta_id = res[0][2]
				meta[meta_name] = meta_id
			elif re.findall(r'(\w+)(.*) 0x(\d+)', s):
				res = re.findall(r'(\w+)(.*) 0x(\d+)', s)
				meta_name = res[0][0].strip().replace(".","")
				meta_id = res[0][2]
				meta[meta_name] = meta_id
			elif re.findall(r'((\w+\s)+) (.*) (\d+)',s):
				res = re.findall(r'((\w+\s)+) (.*) (\d+)',s)
				meta_name = res[0][0].strip().replace(".","")
				meta_id = res[0][-1]
				meta[meta_name] = meta_id
			elif re.findall(r'(\w+)(.*)  (\d+)', s):
				res = re.findall(r'(\w+)(.*)  (\d+)', s)
				meta_name = res[0][0].strip().replace(".","")
				meta_id = res[0][2]
				meta[meta_name] = meta_id
			elif re.findall(r'0x(\d+)(.*)  (.*)', s):
				res = re.findall(r'0x(\d+)(.*)  (.*)', s)
				meta_name = res[0][2].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)         (.*)    (.*)', s):
				res = re.findall(r'(\d+)         (.*)    (.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)         (.*) - (.*)', s):
				res = re.findall(r'(\d+)         (.*) - (.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			elif re.findall(r'(\d+)         (.*): (.*)', s):
				res = re.findall(r'(\d+)         (.*): (.*)', s)
				meta_name = res[0][1].strip().replace(".","")
				meta_id = res[0][0]
				meta[meta_name] = meta_id
			
			else:
				
				nw_sen.append(s)

		# print meta
		return copy.deepcopy(meta), nw_sen

	def find_subfield(self, section_field):

		print("Find sub field  ===============")
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
	def isfixedValuetitle(self, s):
		title =["Type   Description","LS Type   Description","Type   Link ID"]

		if s.strip() in title:
			return True
		elif "_______" in s.strip():
			return True
		else:
			return False

	def isPktMeta(self, s):

		title =["Type   Description","LS Type   Description","Type   Link ID"]

		if re.findall(r'^\d+ - \w+', s):
			return True
		elif re.findall(r'(\d+)      (.*)', s):
			return True
		elif re.findall(r'(\d+)         (.*)    (.*)', s):
			return True
		elif re.findall(r'(\d+)         (.*) - (.*)', s):
			return True
		elif re.findall(r'(\d+)         (.*): (.*)', s):
			return True
		elif re.findall(r'(\w+) - (\d+)', s):
			return True
		elif re.findall(r'(\w+)(.*) 0x(\d+)(.*)  (\d+)', s):
			return True
		elif re.findall(r'0x(\d+)(.*)  (.*)', s):
			return True
		elif s.strip() in title:
			return True
		elif "_______" in s.strip():
			return True
		else:
			return False
		pass

	def get_subfname(self, sen, fn, rf, nlp):

		meta={}
		flag = False
		rules ={}
		rules[fn] =[]

		for s in sen:
			# print(s)
			if self.isPktMeta(s):
				if not flag:
					rules[fn].append(s)
					# print("in fn!")
				else:
					rules[meta_name].append(s)
					# print("in sub")

				continue
			if re.findall(r'(\w+)\) (.*) \(Type Code (.*)\)', s):
				res = re.findall(r'(\w+)\) (.*) \(Type Code (.*)\)', s)
				meta_name = res[0][1]
				meta_id = res[0][2]
				meta[meta_name] = meta_id
				rules[meta_name]=[]
				flag = True
			elif s.endswith(rf):
				# flag = True
				# print(s)
				tmp = s.rstrip(rf)
				tmp = re.sub('(\w+)\)','',tmp).strip()
				doc = nlp(tmp)
				for chunk in doc.noun_chunks:
					if chunk.text == tmp:
						meta_name = tmp
						flag = True
				# meta_name
						# print(tmp)
						rules[tmp] = []
						meta[tmp] = 0xff
						break

			else:
				if not flag:
					rules[fn].append(s)
					# print("in fn!")
				else:
					rules[meta_name].append(s)
					# print("in sub")
		return rules, meta, flag

	def pkt_format_unsepcial(self):

		section_list = OrderedDict()

		# print self.section_file
		f = open(self.section_file, 'r')
		lines = f.readlines()
		f.close()
		tmp =[]
		for line in lines:
			if self.isSectiontitle(line):
				# section_name = self.get_section_title(line)
				section_name = line.strip()
				section_list[section_name]=[]
				# print section_name
				continue
			
			if line == '\n':
				if tmp:
					# tmp = " ".join(tmp)
					# tmp = self.pre_process_rules_nw(tmp, "",False)
					tmp = " ".join(tmp)
					section_list[section_name].append(tmp)
					tmp =[]
			else:
				tmp.append(line.strip())
				# section_list[section_name].append(line)
		# print section_list
		pass
		# print self.key_words

		self.get_rule_sentence(section_list)
		
	
	def get_rule_sentence(self, section_list):
		
		count =0
		for sec, segs in section_list.items():

			print( sec+"===========")
			
			for seg in segs:
				# print seg
				sents = nltk.sent_tokenize(seg)
				for sent in sents:
					for key in self.key_words:
						if key in sent and "MUST" in sent:

							sent = self.mark_keywords(sent)
							word = nltk.word_tokenize(sent)
							tag = nltk.pos_tag(word)
							# print word
							sentence, pos = self.get_sent_speach(tag)
							print( "###########################")
							print( sentence)

							rules = self.pos_pattern_match_nw2(sentence, pos,False, True)
							print( rules)
							print( "##########################")
							count +=1
							break

		print(count) 
		pass

	def pkt_format_rule(self):

		nlp = spacy.load("en")
		rf = self.json_data["packet_format"]["format"]["rfield"]
		
		field_section, struct_list = self.split_field_section(nlp)
		# print(field_section)
		pkt_rules={}

		# for sec , fname in field_section.items():
		# 	print(sec)
		# 	for fn, sen in fname.items():
		# 		print(fn)
		# 		print(sen)
		# mt_if = {}
		for sec, fname in field_section.items():
			# print("----------------------")
			# print("Section:", sec)
			# print(fname)
			
			pkt_rules[sec]={}
			
			
			for fn, sen in fname.items():
				# print("--------")
				# print("filename:", fn)
				# print fn, "==="
				pkt_rules[sec][fn]={}

				subsen, submeta, subflag = self.get_subfname(sen, fn, rf, nlp)

				if subflag:
					# print submeta
					for subn, subs in subsen.items():
						pkt_rules[sec][fn][subn] = {}


						# print("---")
						# print("subname:",subn) 
						self.add_key_words(subn)
					
						meta, nw_sen = self.get_pkt_meta(subs)
						# print(meta, nw_sen)
						pkt_rules[sec][fn][subn]["meta"] = meta

						if meta:
							self.add_key_words_list(meta.keys())
							self.mt_if[subn] = meta
						if not nw_sen:
							continue
						s =self.pre_process_rules_nw(nw_sen, fn, True)
						# print()
						# print(s)
						rules = self.get_common_rules_nw(s, False)
						# print(rules)
						# # print rules

						pkt_rules[sec][fn][subn]["rules"]=rules
				
				else:

					meta, nw_sen = self.get_pkt_meta(sen)
					# print("==========")
					# print(meta, nw_sen)
					if meta:
						self.add_key_words_list(meta.keys())
						self.mt_if[fn] = meta
						
					pkt_rules[sec][fn]["meta"] = meta
					if not nw_sen:
						continue
					# print(self.key_words)
					s =self.pre_process_rules_nw(nw_sen, fn, True)
					# print("preprocess !")
					# print(s)

					rules = self.get_common_rules_nw(s, False)
					# print(rules)

					pkt_rules[sec][fn]["rules"]=rules

		# # 			# pkt_rules[sec][fn]["meta"]= meta
		with open("../output/result_of_extractor/tmp/pktrule-tmp"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(pkt_rules, f, indent=4)

		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
			self.json_tmp  = json.load(f)
		self.json_tmp["Value_list"] = self.mt_if

		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(self.json_tmp, f, indent=4)
			# print "ok"
			# json.dump(self.struct_configure, f,indent=4)
		# print( "===========================")
		self.write_in_json(pkt_rules)
		# self.write_meta_in_json(pkt_rules)

	def write_in_json(self, pkt_rules):
		
		rule ={}
		
		# with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
		# 	self.json_tmp  = json.load(f)


		for sec, field in pkt_rules.items():
			# print sec
			for fn, rul in field.items():

				if "meta"  not in rul.keys() or  "rules" not in rul.keys():
					continue

				# if not rul["meta"] and not rul["rules"]:
				# 	continue

				if not rul["rules"]:
					continue

				if fn == "SECTION_RULES":
					rule["OP"] = {"USE": sec}

				else:

					
					rule["OP"]={"USE": fn}
					rule["Structure"] = {"struct_name": sec, "field": fn, "offset": self.getoffset(sec, fn)}
					# rule["BitWidth"]=self.field_bw_list[sec][fn]
				if rul["rules"]:

					rule["Cond"]=rul["rules"]
				

				# if rul["meta"]:

				# 	rule["Cond"] = self.change_meta2rule(rul["meta"], fn)

				self.Rules["Rules"].append(copy.deepcopy(rule))
				rule={}
		isExists = os.path.exists("../output/result_of_extractor")
		if not isExists:
			os.makedirs("../output/result_of_extractor")
		with open("../output/result_of_extractor/pktrule-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(self.Rules, f, indent=4)

	def getoffset(self, sec, fn):
		str_list = self.struct_configure["Struct_list"]
		for stct in str_list:
			if stct["struct_name"] == sec:
				for i in range(0, len(stct["fieldname"])):
					if stct["fieldname"][i] == fn:
						return i
		return -1
	


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

		isExists = os.path.exists("../output/resutl_of_extractor")
		if not isExists:
			os.makedirs("../output/resutl_of_extractor")

		with open("../output/resutl_of_extractor/meta-info-pkt"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(meta_infos, f, indent=4)
	def get_pkt_rules(self):

		if self.pkt_ftype == 0:    # for dhcp 's type 
			self.pkt_format_unsepcial()
		elif self.pkt_ftype == 1:   # for bgp 's type
			self.pkt_format_rule()
			# self.pkt_format_rule_test()
		elif self.pkt_ftype == 2:   # option 
			self.pkt_format_section()
			# self.pkt_format_unsepcial()


		pass 
	def pkt_format_section(self):

		option_rule={
			"option_name":"",
			"code": "",
			"len":"",
			"value":[],
			"rfc_conds":[]

		}
		option_rules = []
		section_list = OrderedDict()
		f = open(self.section_file, 'r')
		lines = f.readlines()
		f.close()
		tmp =[]
		for line in lines:
			if "Code   Len" in line:
				continue
			if self.isSectiontitle(line):

				sname = self.get_section_title(line)
				self.add_key_words(sname)
				section_list[sname]=[]
				continue

			if line == '\n':
				if tmp:
					# tmp = " ".join(tmp)
					# tmp = self.pre_process_rules_nw(tmp, "",False)
					tmp = " ".join(tmp)
					section_list[sname].append(tmp)
					tmp =[]
			else:
				tmp.append(line.strip())
				pass
		# print section_list
		if tmp:
			tmp = " ".join(tmp)
			section_list[sname].append(tmp)
		# self.write_in_custom()
		section_rule = self.get_rule_section(section_list)

		with open("../output/resutl_of_extractor/meta-info-option-"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
			option_data = json.load(f)
		
		for op, value in option_data.items():
			print(op)
			op_rul = copy.deepcopy(option_rule)

			op_rul["option_name"]= op
			op_rul["code"] = value[0]
			op_rul["len"]= value[1]
			op_rul["value"] = value[2]
			op_rul["rfc_conds"]=section_rule[op]

			option_rules.append(copy.deepcopy(op_rul))
		with open("../output/resutl_of_extractor/pktrule-option-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(option_rules, f, indent=4)

		


	def get_rule_section(self, section_list):


		# self.key_words.append("code")
		self.key_words.append("length")
		
		# print( self.key_words)
		section_rule={}

		for sec, segs  in section_list.items():
			print( "section name: "+ sec)
			section_rule[sec] =[]

			for seg in segs:
				sents = nltk.sent_tokenize(seg)

				for sent in sents:
					if "MUST" in sent or "length " in sent:
						# print(sent)
						sent = self.mark_keywords(sent)
						word = nltk.word_tokenize(sent)
						tag = nltk.pos_tag(word)
						# print word
						sentence, pos = self.get_sent_speach(tag)
						# print "###########################"
						print(sentence) 
						print(pos) 
						

						if ", CC" in pos:
							rul =[]
							s = sentence.split(", ")
							p = pos.split(", ")
							for i in range(0, len(s)):
								rules = self.pos_pattern_match_nw2(s[i], p[i],False, False)
								print(rules) 
								if rules:
									rul.append(rules)
							
							
							if len(rul) == 2:
								if rul[0]["keyword"] == rul[1]["keyword"]:
									rul[0]["rfc_cond"]+=rul[1]["rfc_cond"]
									rul[0]["type"]=3
									rul[0]["connect"] = 1

									rul = rul[0]
							# print rul
							section_rule[sec]= rul

								
						else:
							rules = self.pos_pattern_match_nw2(sentence, pos, False, False)
							print(rules) 
						
							section_rule[sec].append(rules)

						# sent = self.mark_keywords(sent)
						# word = nltk.word_tokenize(sent)
						# tag = nltk.pos_tag(word)
						# # print word
						# sentence, pos = self.get_sent_speach(tag)

						# # print "###########################"
						# print sentence
						# rules = self.pos_pattern_match_nw2(sentence, pos,False, True)
						# print rules
			print( "-----------")

		print(section_rule) 
		return section_rule

	def get_field_bw(self, bw):

		bw_len = int((len(bw)+1)/2)
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
		elif re.findall(r'(.*) \(\d+\)',bw_name):
			bw_len = re.findall(r'\((.*)\)', bw_name)
			bw_len = int(bw_len[0])*8
			bw_name = re.findall(r'(.*) \(\d+\)',bw_name)
			bw_name = bw_name[0].strip()
			
		# bw_name= bw_name.strip()
		# print bw_len, bw_name
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

	def get_meta_special(self):

		if self.pkt_pos == 1:
			self.get_picture_bw_nw()
		elif self.pkt_pos == 2:
			self.get_asn_bw()
		elif self.pkt_pos == 3:
			self.get_stru_bw()
		elif self.pkt_pos == 4:
			self.get_picture_bw_simple()
        
		self.get_struct_expansion()


		isExists = os.path.exists("../output/result_of_extractor")
		if not isExists:
			
			os.makedirs("../output/result_of_extractor")
		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			
			json.dump(self.struct_configure, f,indent=4)
		self.write_explicit_rule()

	def write_explicit_rule(self):

		self.Rules["Rules"]=[]

		for pkt_struct in self.struct_configure["Struct_list"]:

			if 0 not in pkt_struct["value"]:
				count = sum(pkt_struct["value"])
				rule = {}
				rule["OP"]={"USE": pkt_struct["struct_name"],"Implicit": 1}
				rule["Structure"]={"structr_name": pkt_struct["struct_name"]}
				rule["Cond"]=[{"rfc_cond":[{"lhs": "x", "predicate": 35, "rhs": count }], "connect":[], "type":1, "keyword": pkt_struct["struct_name"]}]

				self.Rules["Rules"].append(copy.deepcopy(rule))
			if "TLV" in pkt_struct["struct_name"]:
				rule = {}
				rule["OP"]={"USE": pkt_struct["struct_name"],"Implicit": 1}
				rule["Structure"]={"structr_name": pkt_struct["struct_name"]}
				rule["Cond"]=[{"rfc_cond":[{"lhs": "x", "predicate": 35, "rhs": "y" }], "connect":[], "type":1, "keyword": pkt_struct["struct_name"]}]

				self.Rules["Rules"].append(copy.deepcopy(rule))

	def get_struct_expansion(self):
		f = open(self.section_meta_file, "r")
		lines = f.readlines()
		f.close()
		section_num = {}

		for i in range(0, len(lines)):
			if self.isSectiontitle(lines[i]):
				name = self.get_section_title(lines[i])

				num = lines[i].replace(name, "").strip()[:-1]
				section_num[num] = name
				# logging.info(section_num)
				# logging.info(name)

				# self.struct_expansion[name]=[]
			
			if "see Section " in lines[i].strip():
				tmp = re.findall(r'\|(.*) \(see Section (.*)\)', lines[i].strip())
				fname = tmp[0][0].strip()
				sec = tmp[0][1]
				

				if fname == "":
					db_fname = []
					linum = i-1
					while "-+-+-+-" not in lines[linum]:
						tmp1 = re.findall(r'\|(.*)\|', lines[linum])

					
						db_fname.append(tmp1[0].replace("(variable length)","").strip())
						linum -= 1
					db_fname.reverse()
					# logging.info(db_fname)
					fname = " ".join(db_fname)

				# logging.info((fname,sec))
				if name in self.struct_expansion.keys():

					self.struct_expansion[name].append((fname,sec))
				else:
					self.struct_expansion[name]=[]
					self.struct_expansion[name].append((fname, sec))
				
						

				# logging.info(sec)
		logging.info(section_num)	
		logging.info(self.struct_expansion)
		str_list_exp ={}

		for k, fs in self.struct_expansion.items():

			

			for str_list in self.struct_configure["Struct_list"]:

				if str_list["struct_name"] == k:
					tmp_str = copy.deepcopy(str_list)
					logging.info(tmp_str)


					for f in fs:
						idx = tmp_str["fieldname"].index(f[0])

						for str_li in self.struct_configure["Struct_list"]:

							if str_li["struct_name"]  ==  section_num[f[1]]:
								value_list = str_li["value"]
						tmp_str["value"][idx] = value_list
						tmp_str["fieldname"][idx] =tmp_str["fieldname"][idx]+"  "+str(len(value_list))
			tmp_str["struct_name"] = tmp_str["struct_name"]+"_EXPAND"
			tmp_str["value"] = self.flatten(tmp_str["value"])
			logging.info(tmp_str)
			self.struct_configure["Struct_list"].append(copy.deepcopy(tmp_str))

	def flatten(self, li):
		return sum(([x] if not isinstance(x, list) else self.flatten(x) for x in li), [])


	def get_asn_bw(self):

		f =open(self.section_meta_file, "r")
		lines = f.readlines()
		f.close()


	def get_stru_bw(self):
		f = open(self.section_meta_file,"r")
		lines = f.readlines()
		f.close()

		stu_list ={}
		for line in lines:
			if self.isSectiontitle(line):
				sname = self.get_section_title(line)
				stu_list[sname]=[]
			# elif 

		# print lines

	def get_picture_bw_nw(self):

		f = open(self.section_meta_file, "r")
		lines = f.readlines()
		f.close()

		pkt_bw={}

		field_res = ""
		field_bw =[]

		# self.field_bw_list=OrderedDict()
		bw_name_flag = False
		bw_len_flag = False
		space_flag = False
		bw_name = ""
		
        # isExists = os.path.exists("tmp/"+self.section_meta_file.replace(".txt", ".json"))
	
		path = self.section_meta_file.replace(".txt", ".json")
		logging.info(path)
		isExists = os.path.exists(path)
		if isExists:
			logging.info("is ok!")
			with open(path, "r") as f:
				self.struct_configure = json.load(f)
		else:
			self.struct_configure={"Struct_list":[]}
		
		# print( "GET PACKET FIELD BITWIDTH IN PICTURE")

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
					# print(bw_temp)

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
		
		# print( self.field_bw_list)
		for k, v in self.field_bw_list.items():
			tmp_str = {}
			if not v:
				continue 
			ff = False
			# if we have the structure meta in the dir, we use it.
			for sn in self.struct_configure["Struct_list"]:
				if sn["struct_name"] == k:
					ff = True
					break
			if ff:
				continue
            # if k in self.struct_configure["Struct_list"].keys():
            #     continue
			tmp_str["struct_name"]=k
			tmp_str["value"]=[]
			tmp_str["fieldname"]=[]

			for kk, vv in v.items():
				tmp_str["value"].append(vv)
				tmp_str["fieldname"].append(kk)
				self.add_key_words(kk)
			self.struct_configure["Struct_list"].append(tmp_str)
		# print self.struct_configure


	def get_tlv_field_bw(self, line):

		line = line.split("|")

		code = line[1].strip()
		length = line[2].strip()
		
		value =[]
		if length == "1":

			v = line[3].strip()
			if "/" in v:
				value = v.split("/")
				value = [int(v) for v in value]
			elif "-" in v:
				vrange = v.split("-")
				s = int(vrange[0])
				l = int(vrange[1])

				for i in range(s, l+1):
					value.append(i)
		print(code, length, value)

		return (code, length, value)

	def get_picture_bw_simple(self):

		f = open(self.section_meta_file, "r")
		lines = f.readlines()
		f.close()


       

		self.opt_bw={}

		noflag = False

		print( "GET PACKET FIELD BITWIDTH IN SIMPLE PICTURE")
		for line in lines:

			if self.isSectiontitle(line):
				sname = self.get_section_title(line)

				self.opt_bw[sname] = ()
			elif "+-----+-----+" in line:
				pass
			elif "|" in line:
				if noflag:
					noflag = False
					continue
				line = line.strip()
				print(line)
				self.opt_bw[sname] = self.get_tlv_field_bw(line)	
				
			else:
				noflag = True
		print(self.opt_bw)

		isExists = os.path.exists("../output/tmp")
		if not isExists:
			# print "ok"
			os.makedirs("../output/tmp")

		with open("../output/resutl_of_extractor/meta-info-option-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			# print "ok"
			json.dump(self.opt_bw, f,indent=4)
		print( "===========================")
		pass


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