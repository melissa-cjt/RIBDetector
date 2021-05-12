import sys
import nltk
import re
import copy

class RFC_Extract():

	def __init__(self):	

		self.model_keywords=["MD VB","MD DT VB","MD RB VB"]
		self.verb_keywords = ["VBZ RB","VBP RB"]
		self.compare_keywords = ["JJR IN","IN JJS"]

		self.equal_pattern = {"(.*) MD VB VBN TO (.*)": 4,"(.*) MD VB (.*)":3,"(.*) MD DT VB (.*)":3}
		self.equal_special =["reject"]

		self.unequal_pattern = {"(.*) MD RB VB (.*)":3}
		self.unequal_special = ["always"]

		self.verb_pattern ={"(.*) VBZ RB (.*)":2, "(.*) VBP RB (.*)":2}

		self.compare_pattern ={"(.*) VBZ JJR IN (.*)":3,"(.*) DT JJR IN (.*)":3,"(.*) VBZ RB JJ TO (.*)":4}
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
				
		line = " ".join(line)
		
		# print line
		line = line.replace(";", ".")
		line = line.replace("--",".")
		if tag:
			line = line.replace(" it ", " "+fn+" ")
			line = line.replace("this field", " "+fn+" ")
		# print line

		line = line.lower()
		

		self.key_words.sort(key=lambda i:len(i), reverse=True)
		for kw in self.key_words:
			if re.findall(kw, line, flags=re.IGNORECASE):
				line = line.replace(kw.lower(), "KW_"+ kw.replace(" ","_"))
		# print line
		

		line = self.replace_common_pattern(line)

		sents = nltk.sent_tokenize(line)
		nwsents = []
		for s in sents:
			if "+" in s:
				continue
			if "extended KW_Length" in s:
				continue
			if "variable-KW_Length" in s:
				continue
			if "attribute KW_Length" in s:
				continue
				
			nwsents.append(s)

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
		return sent, True

	def hasconnect(self, sent, pos):

		sp_sent = sent.split(",")
		sp_pos = pos.split(",")

		nw_pos = []
		nw_sent = []

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

			conn.append(1)
			flag = True
		elif " or " in sent:
			nw_sent = sent.split(" or ")
			flag = True
			conn.append(2)

		if flag:
			nw_pos = pos.split(" CC ")
		else:
			nw_sent = [sent]
			nw_pos =[pos]

		return nw_sent, nw_pos, conn
			
	def model_key_filter(self, sent):
		flag = False
		filter_key=["may","calculate","would","can","should","will","need","contain","use","shall"]
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
		# minflag = False

		for key in sent:
			if "KW_" in key:
				fname = key.replace("KW_","")
				# fname.append(key.replace("KW_","")) 
			# if "minimum" in key:
			# 	minflag = True

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
		# print "ok"
		# print self.pkt_rul
		# if not self.pkt_rul:
		# 	return False, ""

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
			# for r in rul["rfc_conds"]:
			# 	if fname  in r["keyword"]:
			# 		return True, rul["rfc_conds"]
		return False, ""

	def min_pkt_rule(self, keyword, sent):

		for ruls in self.pkt_rul["PacketField"]:
			fname = ruls["FieldName"].replace("SEC ","")
			fname = fname.lower()
			
			for rul in ruls["rfc_conds"] :
				if keyword == rul["keyword"] and fname in sent :
					rhs = rul["rfc_cond"][0]["rhs"]
					return True, rhs

		return False, ""

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
				# print sent
				# print "doadafa"
				# print fname

				minflag, rhs = self.min_pkt_rule(fname, sent)
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
		# must be
		for eq in self.equal_pattern.keys():
			if re.findall(eq, pos):

				
				a = re.findall(eq, pos)

				res = a[0]
				# print res
				# print sent

				lhstag = res[0]
				rhstag = res[1]

				# print len(lhstag.split(" "))
				# print len(rhstag.split(" "))

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

				# print lhssent
				# print lhstag
				# print rhssent
				# print rhstag
				# print predsent
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
				
				nw_sent, nw_tag, count = self.hasconnect(rhssent, rhstag)
				# print count
				# print nw_sent , nw_tag
				if count == 0:
					
					# pre, r = self.sub_compare(nw_sent[0], nw_tag[0])
					# print pre, r


					rule["rhs"], rulflag = self.process_rhs(rhssent, rhstag)
					if rulflag:

						rules["rfc_cond"].append(rule)
						rules["type"] = 1
						flag = True
					# else:
					# 	print "not rule"
					
						pass
					rules["keyword"]=self.getkeylf(lhssent.split(" "))
				elif count == 1:

					# print "sent: "+str(len(nw_sent))
					# print "count:"+str(count)
					nw_sent, nw_tag, conn = self.subconnect(nw_sent[0], nw_tag[0])

					# print nw_sent
					# print nw_tag
					# print conn

					for i in range(0, len(nw_tag)):
						pre, r, rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
						if not rulflag:
							continue
						# print pre, r
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

				# print len(lhstag.split(" "))
				# print len(rhstag.split(" "))

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
				

				# print lhssent
				# print lhstag
				# print rhssent
				# print rhstag
				# print predsent

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

					# print nw_sent

					# print "sent: "+str(len(nw_sent))
					# print "count:"+str(count)

					nw_sent, nw_tag, conn = self.subconnect(nw_sent[0], nw_tag[0])

					# print nw_sent
					# print nw_tag

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

				# print lhssent
				# print rhssent
				# print keysent
				# # print eq
				# print predtag

				rule = {
					"lhs":"x",
					"predicate": 0,
					"rhs": ""
				}

				# keysent = keysent.replace("is ","")
				

				nw_sent, nw_tag, conn = self.subconnect(keysent+" "+ rhssent, predtag+" "+rhstag)

				# print nw_sent
				# print nw_tag
				# print conn
				rulcount=0

				for i in range(0, len(nw_tag)):
					pre, r, rulflag = self.sub_compare(nw_sent[i], nw_tag[i])
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
				# print lhssent
				# print self.getkeylf(lhssent)
				
				rules["keyword"]=self.getkeylf(lhssent.split(" "))

				if rulcount == len(nw_tag):
					flag = False
				else:
					flag = True
				# for i in range(0, len(nw_tag)):

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
			# print "ok"

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
				# print a
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

				# if self.verb_key_filter(rhssent[0]) or self.verb_key_filter(predsent):
				# 	return False, rules

				lhssent = " ".join(lhssent)
				rhssent = " ".join(rhssent)
				keysent = " ".join(predsent)

				# print lhssent
				# print lhstag
				# print rhssent
				# print rhstag
				# print predsent
				if err:

					if self.unclear(sent):
						# print "[LOG] Is unclear !"
						# print fname
						flag, nwrules = copy.deepcopy(self.unclear_pkt_rule(fname, True))
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
		

		elif re.findall("(.*) VBZ ", pos):
			if	re.findall("(.*) VBZ CD", pos):

				rule = {
					"lhs": "x",
					"predicate": 0,
					"rhs": ""
				}

				a = re.findall("(.*) VBZ CD", pos)

				lhstag = a[0]
				# print lhstag
				# # print sent				

				# print len(lhstag.split(" "))
				# print len(rhstag.split(" "))

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
					rhs = str(self.word2num[rhs]) 
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
				a = re.findall("(.*) VBZ (.*)", pos)
				res = a[0]
				lhstag = res[0]
				rhstag = res[1]

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

				# print lhssent
				# print lhstag
				# print rhssent
				# print rhstag
				# print predsent
				if err:

					if self.unclear(rhssent):
						# print "[LOG] Is unclear !"
						# print fname
						flag, nwrules = copy.deepcopy(self.unclear_pkt_rule(fname, True))

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
			

	def pos_pattern_match_nw2(self, sent, pos, err):

		constraint_flag = 0
		connect_flag = 0	
		#print pos
		sent = re.sub(r'or it is (.*) but is not',"|| !=", sent)

		if ">" in sent or "<" in sent or "=" in sent:
			return ""


		pattern = {}

		ismodel = False

		ismodel, rules = self.model_keywords_match(sent, pos)
		# print ismodel
		if ismodel:
			return rules


		iscompare, rules, cflag  = self.compare_keywords_match(sent, pos)
	
		if iscompare:
			return rules
		
		if not cflag:
			isverb , rules = self.verb_keywords_match(sent, pos, err)
			# print sent
			# print isverb, rules
			if isverb:
				# print rules
				return rules
		
		return ""


	def get_common_rules_nw(self, sents, err):

		common_rules=[]
		for sent in sents:
			
			if "KW_" not in sent:
				continue
			# print sent
			word = nltk.word_tokenize(sent)
			tag = nltk.pos_tag(word)
			sentence, pos = self.get_sent_speach(tag)
			

			# print " "
			rules = self.pos_pattern_match_nw2(sentence, pos, err)
			
			if rules:
				common_rules.append(rules)
		
		return common_rules




