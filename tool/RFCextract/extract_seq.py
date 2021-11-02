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



class RFC_Seq_Rules_Extract(Extract, RFC_Extract):


	def __init__(self):
		
		super(RFC_Seq_Rules_Extract, self).__init__()
		RFC_Extract.__init__(self)
		self.seqtype = 1
		self.meta_event_regx = ""
		self.meta_state_regx = ""
		self.mandatory_regx = ""
		self.meta_event = {}
		self.meta_state = []
		self.fsm = []
		self.src_state_regx =""
		self.dest_state_regx = {}
		self.event_regx = {}
		self.action = []


	def get_event_state_meta(self):
		self.meta_event_regx = self.json_data["FSM"]["meta_regx"]["event"]
		self.meta_state_regx = self.json_data["FSM"]["meta_regx"]["state"]
		self.mandatory_regx = self.json_data["FSM"]["meta_regx"]["Mandatory"]
		
		f = open(self.section_file_fsm, "r")
		lines = f.readlines()
		f.close()
		# print(self.meta_event_regx)

		for line in lines:
			# print(self.meta_event)
			# print(line)
			line = line.rstrip()
			if re.findall(self.meta_event_regx, line):
				# print("ok")

				tmp_meta = re.findall(self.meta_event_regx, line )
				self.meta_event[tmp_meta[0][0]] = tmp_meta[0][1]
				tmp_event = tmp_meta[0][0]
			elif re.findall(self.meta_state_regx, line):
				tmp_meta = re.findall(self.meta_state_regx, line)
				self.meta_state.append(tmp_meta[0])

			elif self.mandatory_regx != "NONE":
				if re.findall(self.mandatory_regx, line):
					self.meta_event.pop(tmp_event)
			
		# print(self.meta_event)
		# print(self.meta_state)

		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'r') as f:
			json_tmp  = json.load(f)
		json_tmp["Value_list"]["event"] = self.meta_event
		json_tmp["Value_list"]["state"] = self.meta_state
		json_tmp["Value_list"]["action"] = []
		for k, v in self.json_data["FSM"]["fsm_regx"]["action"].items():
			json_tmp["Value_list"]["action"].append(v)

		with open("../output/result_of_extractor/meta-info-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(json_tmp,f, indent=4)
		# print lines

	def fsm_extract(self):
		

		self.src_state_regx = self.json_data["FSM"]["fsm_regx"]["src_state"]
		self.dest_state_regx = self.json_data["FSM"]["fsm_regx"]["dest_state"]
		self.event_regx = self.json_data["FSM"]["fsm_regx"]["event"]
		self.action_regx = self.json_data["FSM"]["fsm_regx"]["action"]


		# print(self.dest_state_regx)
		f = open(self.section_file_fsm, "r")
		lines = f.readlines()
		f.close()
		sflag = False

		eventl = []
		Idlist = []
		state_section ={}
		actionl =[]
		ev_flag = True
		for line  in lines:

			if re.findall(self.src_state_regx, line):
				src_state = re.findall(self.src_state_regx, line)[0]
				sflag = True
				state_section[src_state]=[]
				# print(src_state)
			if not sflag:
				continue
			if line != "\n":
				state_section[src_state].append(line.strip())
		# print(state_section)

		for src, line in state_section.items():
			line = " ".join(line)
			lines = nltk.sent_tokenize(line)

			for line in lines:
				# print(line)

				if re.findall(self.event_regx["Single"], line):
					eventl = re.findall(self.event_regx["Single"], line)
					# print(eventl)	
				elif re.findall(self.event_regx["Multi"], line):
					Id = re.findall(self.event_regx["Multi"], line)
					for i in Id:
						Id = i.split(",")
					for i in Id:
						if "-" in i:
							l = i.split("-")
							for j in range(int(l[0]),int(l[1])+1):
								eventl.append(str(j))
						else:
							eventl.append(i)
				# event_tmp=[]
				# for ev in eventl:
				# 	if ev not in self.meta_event.keys():
				# 		ev_flag = False 
						
				# 	else:
				# 		ev_flag = True
				# 		event_tmp.append(ev)

				
				# if not ev_flag:
				# 	continue
					# print(eventl)
				for act_regx in self.action_regx.keys():

					if re.findall(act_regx, line):
						actionl.append(act_regx)

				for regx in self.dest_state_regx["Unchange"]:

					if re.findall(regx, line):
						dest_state = src
						# print(dest_state,"--")
						# print(src, eventl, dest_state)
						self.gen_fsm(src, eventl, dest_state, actionl)
						event1 = []
						actionl =[]
				
				for regx1 in self.dest_state_regx["Change"]:
					if re.findall(regx1, line):
						dest_state = re.findall(regx1, line)[0]
						# print(dest_state,"--")
						# print(src, eventl, dest_state, actionl)
						self.gen_fsm(src, eventl, dest_state, actionl)
						eventl = []
						actionl =[]

		with open("../output/result_of_extractor/fsmrule-"+self.section_file.split("/")[-1].split(".")[0]+".json",'w') as f:
			json.dump(self.fsm,f, indent=4)

	def gen_fsm(self, src, eventl ,dest, action):

		for ev in eventl:
			if ev not in self.meta_event.keys():
				continue
			fsm_list = {}
			fsm_list["trigger"] = ev
			fsm_list["source"] = src
			fsm_list["dest"] = dest
			fsm_list["action"] = list(set(action))
			self.fsm.append(copy.deepcopy(fsm_list))


if __name__ == '__main__':

	pass