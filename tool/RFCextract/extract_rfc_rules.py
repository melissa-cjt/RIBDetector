import sys
import nltk
import re
import copy

class RFC_Extract(object):

	def __init__(self):	

		self.model_keywords=["MD VB","MD DT VB","MD RB VB"]
		self.verb_keywords = ["VBZ RB","VBP RB"]
		self.compare_keywords = ["JJR IN","IN JJS"]

		self.equal_pattern = {"(.*) MD VB VBN TO (.*)": 4,"(.*) MD VB (.*)":3,"(.*) MD DT VB (.*)":3}
		self.equal_special =["reject"]

		self.unequal_pattern = {"(.*) MD RB VB (.*)":3}
		self.unequal_special = ["always"]

		self.verb_pattern ={"(.*) VBZ RB (.*)":2, "(.*) VBP RB (.*)":2}

		self.compare_pattern ={"(.*) VBZ JJR IN (.*)":3,"(.*) DT JJR IN (.*)":3,"(.*) VBZ JJ TO (.*)":3,"(.*) VBP VBN IN (.*)":3, "(.*) VBZ RB JJ TO (.*)":4}
		self.compare_special = ["greater"]

		self.connect_pattern={"(.*) CC (.*)":1}

		self.word2num={
			'zero': 0,
			'one': 1,
			'two': 2,
			'three': 3,
			'four': 4,
			'five': 5,
			'six': 6,
			'seven': 7,
			'eight': 8,
			'nine': 9,
			'ten': 10,
		}
	def mark_keywords(self, line):

		line = line.lower()
		self.key_words.sort(key=lambda i:len(i), reverse=True)
		for kw in self.key_words:
			kwl = kw.split(" ")
			if len(kwl) == 1:
				tmpl = line.split(" ")
				# print tmpl
				for i in range(0, len(tmpl)):
					# tmpl[i]
					if tmpl[i].replace("'","") == kw.lower():
						tmpl[i] = "KW_"+tmpl[i].replace("'","")
				line = " ".join(tmpl)	
			else:
				if re.findall(kw, line, flags=re.IGNORECASE):
					line = line.replace(kw.lower(), "KW_"+ kw.replace(" ","_"))
		
		return line


	def pre_process_rules(self, line):

		line = " ".join(line)
		line = line.lower()
		
		self.key_words.sort(key=lambda i:len(i), reverse=True)
		for kw in self.key_words:
			if re.findall(kw, line, flags=re.IGNORECASE):
				line = line.replace(kw.lower(), kw.replace(" ","_"))
		
		return line

	def replace_common_pattern(self, line):

		line = line.replace("the value of the ","")
		return line
		# pass
	
			
	def pre_process_rules_nw(self, line, fn, tag):
		# print(line)
				
		line = " ".join(line)

		
		# print line
		line = line.replace(";", ".")
		line = line.replace("--",".")
		if tag:
		
			line = line.replace(" it ", " "+fn+" ")
			line = line.replace("this field", " "+fn+" ")

		nwsents = []
		sents = nltk.sent_tokenize(line)

		for s in sents:
			  

			line = self.mark_keywords(s)
			# print(line)
		

			line = self.replace_common_pattern(line)
		
			if "+" in s:
				continue
			if "extended KW_Length" in s:
				continue
			if "variable-KW_Length" in s:
				continue
			if "attribute KW_Length" in s:
				continue
				
			nwsents.append(line)
		# print(nwsents)
		return nwsents
			

	def get_sent_speach(self,tag):

		sent = []
		part_of_speach = []
		for t in tag:
			sent.append(t[0])
			part_of_speach.append(t[1])
	
		sentence = " ".join(sent)
		pos = " ".join(part_of_speach)

		return sentence , pos

	def isspecial(self, key, sp):
		flag = False

		for s in sp:
			if s in key:
				return True

	def hascompare(self, pos):

		for k in self.compare_keywords:
			if k in pos:
				return True
		return False
	def hasmodel(self, pos):

		for k in self.model_keywords:
			if k in pos:
				return True
		return False
	

	def process_rhs(self, sent, pos):

		if "all ones" in sent:
			return "0xffffffffffffffffff", True
		if "DT JJS " in pos:
			return "", False
		if "VBN" in pos:
			if "sent" in sent:
				return "", False
		if "described in" in sent:
			return "", False
		# if "CD IN NNP" in pos:
			
			
		return sent, True

	def hasconnect(self, sent, pos):

		if "," not in sent:
			return [],[], 0

		sp_sent = sent.split(",")
		sp_pos = pos.split(",")

		nw_pos = [sp_pos[0]]
		nw_sent = [sp_sent[0]]

		count = 0

		for i in range(0, len(sp_pos)):


			if self.hascompare(sp_pos[i]):
				
				nw_pos.append(sp_pos[i])
				nw_sent.append(sp_sent[i])
				count +=1
			
			if self.hasmodel(sp_pos[i]):
				if "may" in sp_sent[i]:
					continue
				
				nw_pos.append(sp_pos[i])
				nw_sent.append(sp_sent[i])
				count +=1

		return  nw_sent, nw_pos, count

	def subconnect(self, sent, pos):

		flag = False
		conn =[]
	
		if " and " in sent:
			nw_sent = sent.split(" and ")
			# print nw_sent
			nw_pos = pos.split(" CC ")
			conn.append(1)
			flag = True
		elif " or " in sent:
			nw_sent = sent.split(" or ")
			flag = True
			nw_pos = pos.split(" CC ")
			conn.append(2)

		if  not flag:
			nw_sent = [sent]
			nw_pos =[pos]

		return nw_sent, nw_pos, conn
			
	def model_key_filter(self, sent):
		flag = False
		filter_key=["may","calculate","would","can","should","will","need","contain","use","shall","might"]
		if "should be set to" in sent:
			return False
		for f in filter_key:
			if f in sent:
				return True
		return flag 

	def verb_key_filter(self, key):
		flag = False
		filter_key = ["allows","defines","elaborates","conflicits","contains"]
		for f in filter_key:
			if f in key:
				return True
		return flag
			
	def compare_count(self, sent, pos):
		count = 0

		if self.hascompare(pos):
			count +=1		
		return count

	def minmax(self, sent):
		flag = False
		# print sent
		if "minimum" in sent:
			# print "ok"
			flag = True
			pre = 35
		elif "maxinum" in sent:
			flag = True
			pre = 37
		else:
			pre = 0
		return flag , pre

	def getkeylf(self, sent):

		fname = ""
		fn = []
		# minflag = False
		# print(sent)
		for key in sent:
			if "KW_" in key:
				# fname = key.replace("KW_","")
				fn.append(key.replace("KW_","")) 
			# if "minimum" in key:
			# 	minflag = True
		if len(fn) == 0:
			fname = ""
		elif len(fn) > 1:
			if "of" in sent:
				fname = fn[0]
			else:
				fname = fn[1]
		else:
			fname = fn[0]
		# if minflag:
		# 	fname = "minimun_"+fname

		return fname

	def findkeylf(self,sent):
		flag = False

		for k in sent:
			if "KW_" in k:
				flag = True
		
		return flag

	def unclear(self, sent):
		flag = False
		uncl = ["expected","recognized","supported","unacceptable","incorrect","malformed","undefined","validity","correctness"]

		for uc in uncl:
			if uc in sent:
				flag = True
		return flag

	def neg_pred(self, pre):

		if pre == 32:
			return 33
		elif pre == 33:
			return 32
		elif pre == 34:
			return 37
		elif pre == 35:
			return 36
		elif pre == 36:
			return 35
		elif pre == 37:
			return 34
		else:
			return 0

	def change_predicate(self, rules):

		nw_rules = rules

		for i in range(0, len(nw_rules)):

			for j in range(0, len(nw_rules[i]["rfc_cond"])):


				nw_rules[i]["rfc_cond"][j]["predicate"] = self.neg_pred(nw_rules[i]["rfc_cond"][j]["predicate"])

			if nw_rules[i]["type"] == 3:
				for k in range(0, len(nw_rules[i]["connect"])):
					# print nw_rules[i]["connect"][k] 
					if nw_rules[i]["connect"][k] == 1:
						nw_rules[i]["connect"][k] = 2
					else:
						nw_rules[i]["connect"][k] = 1
		# print nw_rules
	
		return nw_rules

	def unclear_pkt_rule(self, fname, neg):
		fname = fname.replace("_"," ")
	

		for rul in self.pkt_rul["PacketField"]:

			if rul["FieldName"] == fname:
				# print rul["rfc_conds"]

				if not rul["rfc_conds"]:
					return False, ""

				if neg:
					self.change_predicate(rul["rfc_conds"])
					return True, rul["rfc_conds"]
				else:
					return True, rul["rfc_conds"]
			
		return False, ""
	def unclear_pkt_rule_nw(self, fname, neg):

		fname = fname.replace("_", " ")

		for sec, field in self.pkt_rul.items():

			for f, rul in field.items():
				if f == fname:
					if "rules" not in rul.keys():
						continue

					if not rul["rules"]:
						continue
					if neg: 
						tmp = self.change_predicate(rul["rules"])
						return True, tmp
					else:
						return True, rul["rules"]
		for name, meta in self.meta_rul["Value_list"].items():

			if name == fname:
				tmp = self.change_meta2rule(meta, fname)
				return True, tmp


		return False, ""
	def change_meta2rule(self, metas, fname):
		rules = []
		count = 0

		for k,v in metas.items():
			rul = {}
			rul["lhs"] = "x"
			rul["predicate"]="32"
			rul["rhs"] = v
			rules.append(copy.deepcopy(rul))
			count = count +1
		rfc_cond={}
		rfc_cond["rfc_cond"]=rules
		rfc_cond["connect"]=[2]*count
		rfc_cond["type"] = 3
		rfc_cond["keyword"] = fname
		return rfc_cond
		

		

	def min_pkt_rule(self, keyword, sent):

		for ruls in self.pkt_rul["PacketField"]:
			fname = ruls["FieldName"].replace("SEC ","")
			fname = fname.lower()
			
			for rul in ruls["rfc_conds"] :
				if keyword == rul["keyword"] and fname in sent :
					rhs = rul["rfc_cond"][0]["rhs"]
					return True, rhs

		return False, ""

	def min_pkt_rule_nw(self, keyword, sent):
		# print(self.pkt_rul)

		for sec, field in self.pkt_rul.items():

			for fname, ruls in field.items():
				if fname == "SECTION_RULES":
					fname = sec

				fname = fname.lower()
					# print(fname)
				# print(fname, ruls['meta'])

				if "rules" not in ruls.keys():
					continue
				for rul in ruls["rules"]:
					if keyword.lower() == rul["keyword"] and fname in sent:
						rhs = rul["rfc_cond"][0]["rhs"]
						return True, rhs
		return False, ""
			
	def sub_model(self, sent, pos):
		pass
		predicate = 0
		rhs =""
		flag = False
		# print(sent, pos)
		if "MD VB" in pos:
			if "must be" in sent:

				predicate = 32
				rhs = sent.replace("must be","")
				flag = True
			elif "must be set to" in sent:
				predicate = 32
				rhs = sent.replace("must be set to","")
				flag = True	

		return predicate, rhs, flag

	def sub_compare(self, sent, pos):
		predicate = 0
		rhs =""
		flag = False

		
		if "IN JJS CD" in pos:
			
			if "at least " in sent:
				predicate = 35
				rhs = sent.replace("at least ","")

				rhs = rhs.split(" ")[0]

				if not rhs.isdigit():
					rhs = str(self.word2num[rhs]) 

				flag =True
			pass
		elif "VBP VBN IN" in pos:
			if "are originated by" in sent:
				predicate = 32
				rhs = sent.replace("are originated by","")
				rhs = self.getkeylf(rhs.split(" "))
				if rhs == "":
					flag = False
				else:
					# print(rhs, "ok")
					flag = True
		elif "VBZ JJ TO DT" in pos:
			if "is identical to" in sent:
				predicate = 32
				rhs = sent.replace("is identical to","")
				rhs = self.getkeylf(rhs.split(" "))
				if rhs == "":
					flag = False
				else:
					flag = True			
				# rhs = rhs.split("")
		elif "DT JJR IN CD" in pos:

			if "no greater than" in sent:
				predicate = 37
				rhs = sent.replace("no greater than ","")
				flag = True
			pass
		elif "CC CD" in pos:
			if "either" in sent:
				predicate = 32
				rhs = sent.split(" ")[1]
				
				if not rhs.isdigit():
					rhs = str(self.word2num[rhs]) 

				flag = True
		elif "JJR IN CD" in pos:
			if "less than" in sent:
				predicate = 36
				sent = sent.replace("is ","")
				rhs = sent.replace("less than ","")
				rhs = rhs.split(" ")[0]

				if not rhs.isdigit():
					rhs = str(self.word2num[rhs]) 
				flag = True
			elif "greater than" in sent:
				predicate = 34
				rhs = sent.replace("greater than ","")
				rhs = rhs.split(" ")[0]

				if not rhs.isdigit():
					rhs = str(self.word2num[rhs]) 
				flag = True
				# rhs = sent.split(" ")[-1]
		elif "VBZ RB JJ TO CD" in pos:
			if "equal to" in sent:
				predicate = 33
				sent = sent.replace("is ","")
				rhs = sent.replace("not equal to ","")
				rhs = rhs.split(" ")[0]

				if not rhs.isdigit():
					rhs = str(self.word2num[rhs]) 
				flag = True
	

		elif "JJR IN " in pos:
			# print "JJR IN"
			if "less than" in sent:
				predicate = 36

			if "minimum " in sent:
				fname = self.getkeylf(sent.split(" "))
			
				minflag, rhs = self.min_pkt_rule_nw(fname, sent)
				# print rhs


				flag = True

		else:

			
			flag = False

		return predicate, rhs, flag

	def model_keywords_match(self, sent, pos):
		flag = False
		rules = {
			"rfc_cond":[],
			"connect":[],
			"type":0,
			"keyword":""
		}

		
		for eq in self.equal_pattern.keys():
			
			if re.findall(eq, pos):

				
				a = re.findall(eq, pos)

				res = a[0]
				lhstag = res[0]
				rhstag = res[1]

				sp_sent = sent.split(" ")
				lpos = len(lhstag.split(" "))
				prepos = len(sp_sent) -len(rhstag.split(" "))
				rpos = len(rhstag.split(" "))


				lhssent = sp_sent[0 : lpos]
				

				if not self.findkeylf(lhssent):
					continue

				rhssent = sp_sent[-rpos: ]
				predsent = sp_sent[lpos: prepos]
				
				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)

				if self.model_key_filter(keysent):
					continue
			
				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}

				if self.isspecial(keysent, self.equal_special):
					rule["predicate"] = 33
						# nw_sent = sent.replace(key_words,"!=")
				else:
					rule["predicate"] = 32
				# print rule["predicate"]
				
				nw_sent, nw_tag, count = self.hasconnect(rhssent, rhstag)
				
				if count == 0:
					
					
					nw_sent, nw_tag, conn = self.subconnect(rhssent, rhstag)

					if conn:
						
						for i in range(0, len(nw_tag)):

							if self.hasmodel(nw_tag[i]):
								pre, r , rulflag = self.sub_model(nw_sent[i], nw_tag[i])
								if not rulflag:
									continue
								rule["predicate"] = pre
								rule["rhs"] = r
								rules["rfc_cond"].append(copy.deepcopy(rule))
							if self.hascompare(nw_tag[i]):
								pre, r, rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
								if not rulflag:
									continue
								rule["predicate"] = pre
								rule["rhs"] = r
								rules["rfc_cond"].append(copy.deepcopy(rule))
							# if self.isdigit
							if "CC CD" == nw_tag[i]:
								if "either" in nw_sent[i]:
									rule["predicate"] = 32
									# predicate = 32
									rhs = nw_sent[i].split(" ")[1]
									
									if not rhs.isdigit():
										rhs = str(self.word2num[rhs]) 
									# print(rhs)
									rule["rhs"] = rhs
									rules["rfc_cond"].append(copy.deepcopy(rule))
							pass
						rules["type"]=3
						rules["connect"] = conn	
						
						flag = True
					else:

						rule["rhs"], rulflag = self.process_rhs(rhssent, rhstag)
						if rulflag:

							rules["rfc_cond"].append(rule)
							rules["type"] = 1
							flag = True
					
						pass
					# print(lhssent)
					rules["keyword"]=self.getkeylf(lhssent.split(" "))
					# print(rules)
				elif count == 1:

					rule["rhs"], rulflag = self.process_rhs(nw_sent[0], nw_tag[0])
					if rulflag:
						rules["rfc_cond"].append(copy.deepcopy(rule))
					
				
					nw_sent, nw_tag, conn = self.subconnect(nw_sent[1], nw_tag[1])

					for i in range(0, len(nw_tag)):

						if self.hasmodel(nw_tag[i]):
							pre, r , rulflag = self.sub_model(nw_sent[i], nw_tag[i])
							if not rulflag:
								continue
							rule["predicate"] = pre
							rule["rhs"] = r
							rules["rfc_cond"].append(copy.deepcopy(rule))
						if self.hascompare(nw_tag[i]):
							pre, r, rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
							if not rulflag:
								continue
							rule["predicate"] = pre
							rule["rhs"] = r
							rules["rfc_cond"].append(copy.deepcopy(rule))
						
					
					if conn:
						rules["type"]=3
						rules["connect"] = conn	
					else:
						rules["type"]=1
					rules["keyword"]=self.getkeylf(lhssent.split(" "))
					flag = True
				else:
					pass

				break
		# must not be
		for uneq in self.unequal_pattern.keys():
			if re.findall(uneq, pos):

				
				a = re.findall(uneq, pos)

				res = a[0]
				# print res
				# print sent

				lhstag = res[0]
				rhstag = res[1]

			
				sp_sent = sent.split(" ")
				lpos = len(lhstag.split(" "))
				prepos = len(sp_sent) -len(rhstag.split(" "))
				rpos = len(rhstag.split(" "))


				lhssent = sp_sent[0 : lpos]
				rhssent = sp_sent[-rpos: ]
				predsent = sp_sent[lpos: prepos]
				
				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)

				if self.model_key_filter(keysent):
					continue
				

				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}

				if self.isspecial(keysent, self.unequal_special):
					rule["predicate"] = 32
						
				else:
					rule["predicate"] = 33

				nw_sent, nw_tag, count = self.hasconnect(rhssent, rhstag)
				# print count
				if count == 0:
					
					rule["rhs"], rulflag = self.process_rhs(rhssent, rhstag)
					if rulflag:

						rules["rfc_cond"].append(rule)
						rules["type"] = 1
						flag = True
					# else:
					# 	print "not rule"
						pass
					# rules.append(rule)
					rules["keyword"]=self.getkeylf(lhssent.split(" "))
				elif count == 1:

				
					nw_sent, nw_tag, conn = self.subconnect(nw_sent[0], nw_tag[0])

					# print(nw_sent) 
					# print(nw_tag)

					for i in range(0, len(nw_tag)):
						pre, r,rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
						# print pre, r
						if not rulflag:
							continue
						rule["predicate"] = pre
						rule["rhs"] = r
						rules["rfc_cond"].append(copy.deepcopy(rule))
					if conn:
						rules["type"]=3
						rules["connect"] = conn	
						flag = True
					else:
						rules["type"]=1
						flag = True
					rules["keyword"]=self.getkeylf(lhssent.split(" "))
				else:
					pass
				
					

				break

		return flag, rules

	def compare_keywords_match(self, sent, pos):
		flag = False
		rules = {
			"rfc_cond":[],
			"connect":[],
			"type":0,
			"keyword":""
		}
		cflag = False
		# print("is compare!")

		for eq in self.compare_pattern.keys():
			if re.findall(eq, pos):
				# print sent
				cflag = True
				a = re.findall(eq, pos)

				res = a[0]
				# print res
				# print sent

				lhstag = res[0]
				rhstag = res[1]

				sp_sent = sent.split(" ")
				sp_pos = pos.split(" ")
				lpos = len(lhstag.split(" "))
				prepos = len(sp_sent) -len(rhstag.split(" "))
				rpos = len(rhstag.split(" "))

				lhssent = sp_sent[0 : lpos]

				if not self.findkeylf(lhssent):
					continue

				rhssent = sp_sent[-rpos: ]
				predsent = sp_sent[lpos: prepos]
				predtag = " ".join(sp_pos[lpos: prepos])
				
				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)


				rule = {
					"lhs":"x",
					"predicate": 0,
					"rhs": ""
				}

		
				nw_sent, nw_tag, conn = self.subconnect(keysent+" "+ rhssent, predtag+" "+rhstag)

				
				rulcount=0
				# print(nw_tag)

				for i in range(0, len(nw_tag)):
					pre, r, rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
					# print(pre, r, rulflag)
					if not rulflag:
						rulcount +=1
						continue
					# print pre, r
					rule["predicate"] = pre
					rule["rhs"] = r
					# rules["keyword"]=self.getkeylf(lhssent)
					rules["rfc_cond"].append(copy.deepcopy(rule))

				if conn:
					rules["type"]=3
					rules["connect"] = conn	
				else:
					rules["type"]=1

				
				rules["keyword"]=self.getkeylf(lhssent.split(" "))

				if rulcount == len(nw_tag):
					flag = False
				else:
					flag = True
			
				break
		
		return flag , rules, cflag,



	def verb_keywords_match(self, sent, pos, err):
		flag = False
		rules = {
			"rfc_cond":[],
			"connect":[],
			"type":0,
			"keyword":""
		}

		if re.findall("(.*) (VBZ|VBP) RB ", pos):
		
			if re.findall("(.*) (VBZ|VBP) RB CD", pos):
				pass
				flag = False
			else:
				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}
				a = re.findall("(.*) (VBZ|VBP) RB (.*)", pos)
				
				res = a[0]
				lhstag = res[0]
				rhstag = res[2]

				sp_sent = sent.split(" ")
				lpos = len(lhstag.split(" "))
				prepos = len(sp_sent) -len(rhstag.split(" "))
				rpos = len(rhstag.split(" "))

				lhssent = sp_sent[0 : lpos]

				if not self.findkeylf(lhssent):
					
					return flag, ""

				fname = self.getkeylf(lhssent)
				rhssent = sp_sent[-rpos: ]
				predsent = sp_sent[lpos: prepos]


				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)

				
				if err:

					if self.unclear(sent):
						
						flag, nwrules = copy.deepcopy(self.unclear_pkt_rule_nw(fname, True))
						# print flag
						if not flag:
							# print rhssent
							rule["predicate"] = 33
							rule["rhs"] = rhssent
							
							# print rules["rfc_cond"]
							rules["rfc_cond"].append(copy.deepcopy(rule))
							rules["type"] = 1
							rules["keyword"] = fname

							flag = True
						else:
							rules = nwrules
						# return flag , rules
					else:
						flag = False
		

		elif re.findall("(.*) (VBZ|VBP) ", pos):
			if	re.findall("(.*) (VBZ|VBP) CD", pos):

				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}

				a = re.findall("(.*) (VBZ|VBP) CD", pos)

				lhstag = a[0][0]
			
				sp_sent = sent.split(" ")
				lpos = len(lhstag.split(" "))
				lhssent = sp_sent[0:lpos]
				rhssent = sp_sent[lpos: ]
				

				# print rhssent

				if self.verb_key_filter(rhssent[0]):
					return False, rules
				# print lhssent

				mflag , pre = self.minmax(" ".join(lhssent))

				if mflag:
					rule["predicate"] = pre
				else:
					rule["predicate"] = 32
				rhs = rhssent[1]

				if not rhs.isdigit():
					if rhs in self.word2num.keys():

						rhs = str(self.word2num[rhs]) 
					elif "0x" in rhs:
						rhs = rhs

				rule["rhs"] = rhs
				
				rules["rfc_cond"].append(copy.deepcopy(rule))
				rules["type"] = 1

				rules["keyword"]=self.getkeylf(lhssent)

				flag = True
			else:
				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}
				a = re.findall("(.*) (VBZ|VBP) (.*)", pos)
				res = a[0]
				lhstag = res[0]
				rhstag = res[2]

				sp_sent = sent.split(" ")
				lpos = len(lhstag.split(" "))
				prepos = len(sp_sent) -len(rhstag.split(" "))
				rpos = len(rhstag.split(" "))

				lhssent = sp_sent[0 : lpos]

				if not self.findkeylf(lhssent):
					
					return flag, ""
				
				

				fname = self.getkeylf(lhssent)
				rhssent = sp_sent[-rpos: ]
				predsent = sp_sent[lpos: prepos]


				if self.verb_key_filter(rhssent[0]) or self.verb_key_filter(predsent):
					return False, rules

				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)

				if err:

					if self.unclear(rhssent):
						
						flag, nwrules = copy.deepcopy(self.unclear_pkt_rule_nw(fname, True))
						if not flag:
							# print rhssent
							rule["predicate"] = 32
							rule["rhs"] = rhssent
							
							rules["rfc_cond"].append(copy.deepcopy(rule))
							rules["type"] = 1
							rules["keyword"] = fname
							flag = True
						else:
							rules = nwrules
						
						# return flag , rules
					else:
						flag = False
		else:
			pass
					

		
		return flag, rules
			

	def pos_pattern_match_nw2(self, sent, pos, err, monly):

		constraint_flag = 0
		connect_flag = 0	

		pattern = {}

		ismodel = False
		# print "start extracting ...."

		ismodel, rules = self.model_keywords_match(sent, pos)
		# print ismodel
		if ismodel:
			return rules
		elif monly:
			return ""

		
		iscompare, rules, cflag  = self.compare_keywords_match(sent, pos)
	
		if iscompare:
			return rules
		
		if not cflag:
			isverb , rules = self.verb_keywords_match(sent, pos, err)
			
			if isverb:
				# print rules
				return rules
		
		return ""


	def get_common_rules_nw(self, sents, err):

		common_rules=[]
		for sent in sents:
			
			if "KW_" not in sent:
				continue
			
			word = nltk.word_tokenize(sent)
			tag = nltk.pos_tag(word)
			sentence, pos = self.get_sent_speach(tag)
			
			rules = self.pos_pattern_match_nw2(sentence, pos, err, False)
			
			if rules:
				common_rules.append(rules)
		
		return common_rules




