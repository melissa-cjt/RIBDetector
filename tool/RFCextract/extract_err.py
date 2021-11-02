import re, string
import sys
from xml.etree import ElementTree 
import os
import nltk
import copy
from extract_main import Extract
from extract_rfc_rules import RFC_Extract
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString
from collections import OrderedDict
from time import *
import json

class RFC_ERR_Rules_Extract(Extract, RFC_Extract):

	def __init__(self, meta_info={}):

		# super().__init_(page=None, pkts=None, fsms=None, errs=None, key_words=None, error_codes=None, state=None, event=None, fields=None, format_key=None, section_file=None, pkt_temp=None, fieldname_left=None, fieldname_right= None, rules_left=None, rules_right=None)
		super(RFC_ERR_Rules_Extract, self).__init__()
		RFC_Extract.__init__(self)
		
		self.errcode = None
		self.err_name = None
		self.meta_errcode = None
		self.meta_subcode = None
		

		self.meta_info={}
		self.Rules= None


	def get_errcode(self):

		f = open(self.section_meta_file, 'r')
		lines = f.readlines()
		f.close()
		flag = False
		flagsub = False
		self.meta_errcode ={}
		# self.meta_subcode={}
		self.meta_subcode = OrderedDict()
		self.err_name=[]
		subcode_tmp ={}
		oldname="NONE"
		
		
		for line in lines:
			line = line.strip()
			# print line
			if flag:
				# print line
				res = re.findall(r'(\d)         (.*)   (.*)', line)
				# print res
				if res:
					code_id = res[0][0]
					# code_name = res[0][1].strip().replace(" Error", "")
					code_name = res[0][1].strip()
					self.add_key_words(code_name)

					
					code_name = code_name.replace(" ","_")
					# print code_name
					self.meta_errcode[code_name]=code_id
					self.err_name.append(code_name)

			if flagsub:
				# res = re.findall()
				res = re.findall(r'(\d+) - (.*)', line)
				if res:
					subcode_id = res[0][0]

					subcode_name = res[0][1].replace(".","")
					if "[Deprecated" in subcode_name:
						continue
					self.add_key_words(subcode_name)

					subcode_name = subcode_name.replace(" ","_")
					subcode_tmp[subcode_name]= subcode_id
					self.err_name.append(subcode_name)

				# print res
				pass
				
						
			if "Error code:" in line:
				flag = True
			if "Error subcodes:" in line:
				flagsub = True
				# res= re.findall(r'(.*) Error subcodes:', line)
				res= re.findall(r'(.*) subcodes:', line)


				if res:
					# print res
					self.meta_subcode[res[0].replace(" ","_")] = {}
					# print subcode_tmp
					if oldname != "NONE":
						self.meta_subcode[oldname] = copy.copy(subcode_tmp)
					subcode_tmp={}
					oldname = res[0].replace(" ","_")
				
			if "Data:" in line:
				# print subcode_tmp
				self.meta_subcode[oldname] = copy.copy(subcode_tmp)
	

	def generate_err_metainfo(self):
		self.meta_info = {
			"predict_type":"Function",
			"Dir":"NONE",
			"Function_SW":0,
			"Function_ARG":1,
			"value_num": 1,
			"meta-infos": [],
			"keyword":["error", "notify","err","notification","subcode","code"]

		}

		meta_list = map(int, self.meta_errcode.values())

		self.meta_info["meta-infos"].append(sorted(meta_list))

		meta_list = []

		for k, v in self.meta_subcode.items():

			meta_list = list(set(meta_list+map(int, v.values())))
		
		self.meta_info["meta-infos"].append(sorted(meta_list))
		
		isExists = os.path.exists("../output/resutl_of_extractor")
		if not isExists:
			os.makedirs("../output/resutl_of_extractor")

		# print self.meta_info
		with open("../output/resutl_of_extractor/meta-info-err.json",'w') as f:
			json.dump(self.meta_info, f,indent=4)


	def parse_err_meta(self):
		print ("Getting the meta-info ....")
		# print self.section_meta_file
		self.get_errcode()
		self.generate_err_metainfo()


	def pre_read_pkt_rule(self):
		
		
		with open("../output/tmp/pktrule-tmp"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
			self.pkt_rul  = json.load(f)
		# print(self.pkt_rul)

	def parse_err_handling_nw(self):

		# print ("Getting the rule ...")
		# print self.section_file	
		self.pre_read_pkt_rule()
		rules_section = self.get_err_section()
		# for i in rules_section:
		# 	print i
		# err_rules =
		err_rules = self.get_err_rules_nw(rules_section )
		self.write_in_json(err_rules)
		
	def parse_err_handling_nw_v2(self):

		# print ("Getting the rule ...")
		self.pre_read_pkt_rule()

		rules_section = self.split_err_section()
		# print(rules_section)

		err_rules = self.get_err_rules_nw_v2(rules_section)
		self.write_in_json(err_rules)

	def split_err_section(self):

		f = open(self.section_file_error,'r')
		lines = f.readlines()
		f.close()

		rules_section = {}
		rules_tmp = []

		for line in lines:
			# print line
			if self.isSectiontitle(line):
				section_name = self.get_section_title(line.strip())
				rules_section[section_name]=[]
				pass
			else:
				
				# if there is a null line as the segment sperate place
				if line == "\n":
					# print "null"
					cand_rules = self.pre_process(rules_tmp)
					
					rules_section[section_name].append(cand_rules)
					rules_tmp=[]
					
				else:
					line = line.strip()
					# print line
					rules_tmp.append(line)

		
		return rules_section

		

	def pre_process(self, line):
		line = " ".join(line)
		line = line.lower()
		return line

	def get_err_rules_nw_v2(self, rsections):

		common_rules = []
		tmp_rules = []

		rule_errhd = copy.deepcopy(self.err_subcode)
		# print(self.err_subcode)
		for k,v in rule_errhd.items():
			# pk = k.replace(" ","_")
			for vk, vv in v.items():
				# pvk = vk.replace(" ","_")

				rule_errhd[k][vk]=[]
		# print(rule_errhd)
		# print(self.err_code_name)
		for sec, para in rsections.items():
			for p in para:
				eflag = False
				# print(p)
				sec = self.mark_errcode_insent(p)
				
				sec = self.mark_keyword(sec)
				# print(sec)

				sents = nltk.sent_tokenize(sec)
				for sent in sents:
					rules = {}

					word = nltk.word_tokenize(sent)
					tag = nltk.pos_tag(word)

					sentence, pos = self.get_sent_speach(tag)
					# print "new errorcode"
					if "ERRCODE_" in sentence:
						tmp = sentence.split("ERRCODE_")[1]
						errc = tmp.split(" ")[0]
						# print(errc+'--------------------------------------')
						
						eflag = True
					if "unspecific" in sentence:
						errc = "0"
						# print errc
						sentence = sentence.replace("unspecific","ERRCODE_unspecific")
						eflag = True
					if "notification message should not be sent" in sentence:
						errc= "ERRCODE_IGNORED"
						# print errc 
						sentence = sentence.replace("notification message should not be sent", "ERRCODE_IGNORED")

						eflag = True
					
					nw_sentence, nw_pos = self.spliterr(sentence, pos)
					
				
					rules = self.pos_pattern_match_nw2(nw_sentence, nw_pos, True, False)
					
					if rules:
						
						if type(rules) is dict:
							# print "ok"
							common_rules.append(copy.deepcopy(rules))
						else:
							common_rules += copy.deepcopy(rules)
				
				
					
				if eflag:
				
					rule_errhd = self.generate_errorcode_rules_nw(rule_errhd, errc, copy.deepcopy(common_rules), copy.deepcopy(tmp_rules))
					common_rules = []
					tmp_rules = []
				else:
					tmp_rules= copy.deepcopy(tmp_rules)+copy.deepcopy(common_rules)
					common_rules = []
					pass


		return rule_errhd 

	def get_err_section(self):
		
		f = open(self.section_file, 'r')
		lines = f.readlines()
		f.close()

		rules_section = []
		rules_tmp = []

		for line in lines:
			# print line

			if re.match(r'^\d+\.+', line):
				pass
			else:
				
				# if there is a null line as the segment sperate place
				if line == "\n":
					# print "null"
					cand_rules = self.pre_process_rules(rules_tmp)
					
					rules_section.append(cand_rules)
					rules_tmp=[]
					
				else:
					line = line.strip()
					# print line
					rules_tmp.append(line)

		
		return rules_section


	def mark_errcode_insent(self, sec):

		for errcode in self.err_code_name:
			
			if re.findall(errcode, sec, flags=re.IGNORECASE):
				# print errcode
				# print(errcode)
				sec = sec.replace(errcode.lower(), "ERRCODE_"+errcode.replace(" ","_"))
				# print(sec)
				# sec = re.sub(errcode, "ERRCODE_"+errcode, sec )
			
		return sec

				
	def mark_keyword(self, line):

		spkw={"well-known mandatory attributes": "KW_Path_Attributes","NLRI": "KW_Network_Layer_Reachability_Information","Attribute Length":"KW_Attribute_Length"}

		for sk in spkw.keys():
			if re.findall(sk, line, flags=re.IGNORECASE):
				line = line.replace(sk.lower(), spkw[sk])

		# self.read_key_words("tmp/kw_pktrule_RFC4271.txt")

		for kw in self.key_words:
			if re.findall(kw, line, flags=re.IGNORECASE):
				line = line.replace(kw.lower(), "KW_"+ kw.replace(" ","_"))

		


		return line

	def spliterr(self, sent, pos):

		sentl = sent.split(",")
		posl = pos.split(",")

		nw_sent = []
		nw_pos = []

		for i in range(0, len(sentl)):
			if "ERRCODE_" in sentl[i]:
				pass
			else:
				nw_sent.append(sentl[i])
				nw_pos.append(posl[i])
		
		nw_sent = " ".join(nw_sent)
		nw_pos = " ".join(nw_pos)
		return nw_sent, nw_pos
	
	
	def get_err_rules_nw(self, rsections):

		common_rules = []
		tmp_rules = []

		rule_errhd = copy.deepcopy(self.meta_subcode)

		for k,v in rule_errhd.items():
			for vk, vv in v.items():
				rule_errhd[k][vk]=[]
	
		
		for sec in rsections:
			eflag = False
			# print sec
			
			sec = self.mark_errcode_insent(sec)
			sec = self.mark_keyword(sec)
			# print sec

			sents = nltk.sent_tokenize(sec)

			for sent in sents:
				rules = {}

				word = nltk.word_tokenize(sent)
				tag = nltk.pos_tag(word)

				sentence, pos = self.get_sent_speach(tag)
				# print "new errorcode"
				if "ERRCODE_" in sentence:
					tmp = sentence.split("ERRCODE_")[1]
					errc = tmp.split(" ")[0]
					
					eflag = True
				if "unspecific" in sentence:
					errc = "0"
					# print errc
					sentence = sentence.replace("unspecific","ERRCODE_unspecific")
					eflag = True
				if "notification message should not be sent" in sentence:
					errc= "ERRCODE_IGNORED"
					# print errc 
					sentence = sentence.replace("notification message should not be sent", "ERRCODE_IGNORED")

					eflag = True
				
				nw_sentence, nw_pos = self.spliterr(sentence, pos)
				
			
				rules = self.pos_pattern_match_nw2(nw_sentence, nw_pos, True)
				
				if rules:
					
					if type(rules) is dict:
						# print "ok"
						common_rules.append(copy.deepcopy(rules))
					else:
						common_rules += copy.deepcopy(rules)
			
			# 	print errc 
			# print common_rules
				
			if eflag:
			
				rule_errhd = self.generate_errorcode_rules_nw(rule_errhd, errc, copy.deepcopy(common_rules), copy.deepcopy(tmp_rules))
				common_rules = []
				tmp_rules = []
			else:
				tmp_rules= copy.deepcopy(tmp_rules)+copy.deepcopy(common_rules)
				common_rules = []
				pass
	
		return rule_errhd 
	



	def generate_errorcode_rules_nw(self, errcodes, errc, rules, tmp_rules):


		if tmp_rules is not None:

			rules +=tmp_rules
		errc = errc.replace("_"," ")
		# print rules
		# print errc
		for code, subcodes in errcodes.items():

			if errc in code:
				pass
			
			if errc in subcodes.keys():
				# print errc

				if errcodes[code][errc]:
					
					errcodes[code][errc]+=copy.deepcopy(rules)
				else:
					# print rules
					errcodes[code][errc]=copy.deepcopy(rules)
				# errcodes[code][errc]=copy.deepcopy(rules)
							
			
		return errcodes

	def write_in_json(self, err_rules):

		rule = {}
		self.Rules={}
		self.Rules["Rule"]=[]

		for errcode, subcode in err_rules.items():
			
			for subc, subcrs in subcode.items():
				if not subcrs:
					continue
				# print errcode, subc, subcrs
				
				rule["Op"]={"SET":[int(self.err_code[errcode]), int(self.err_subcode[errcode][subc])]}
				rule["Cond"]=subcrs
				# print subc.split("_")[-1]
			# print "=============="
				# print rule
				self.Rules["Rule"].append(copy.deepcopy(rule))
				rule={}
			
		isExists = os.path.exists("../output/result_of_extractor/tmp")
		if not isExists:
			os.makedirs("../output/result_of_extractor/tmp")
		with open("../output/result_of_extractor/tmp/errrule-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(self.Rules, f, indent=4)


			
if __name__ == '__main__':

	pass

