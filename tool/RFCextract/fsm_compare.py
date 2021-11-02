import re
# from networkx.generators.lattice import triangular_lattice_graph
# from networkx.generators.random_graphs import fast_gnp_random_graph
# from transitions.extensions import GraphMachine as Machine
from transitions import Machine
# import numpy as np
import copy
import sys
# from xml.etree import ElementTree 
import time
import json
# import networkx as nx
# from networkx.algorithms import isomorphism
from collections import Counter
import itertools


class Matter(object):
	pass

class Compare:


    def __init__(self):

        self.rfc_filename = ""
        self.prog_filename = ""
        
        self.state_map = []
        self.prog_states = []
        self.rfc_states = []
      
        self.map_states = {}
        self.map_events ={}
        self.certain_event=[]
        self.rfc_ev = []
        self.rfc_ev_min = []
        self.prog_ev = []
        self.min_rfc_event={}
        self.event_map = []
        self.rfc_transitions = []
        self.min_rfc_transitions=[]
        self.prog_transitions = []
        self.rfc_transitions_full=[]
        self.prog_transitions_full=[]
        self.unknown_event = []
        self.use_event_map ={}
        self.rfc_model = ""
        self.prog_model = ""
        self.rfc_machine = ""
        self.prog_machine = ""
        self.test_rfc = []
        self.test_prog = []  
        self.rstate_inout_state={}
        self.pstate_inout_state={}

        self.initial_rfc_state = ""
        self.initial_prog_state = ""
        self.has_min = False
    def parse_config1(self, rfcf, progf):
      
       
        # with open(filename, 'r') as f:
        #     json_data = json.load(f)
        
        self.rfc_filename = rfcf
        self.prog_filename = progf

        self.rfc_transitions = self.load_data(self.rfc_filename)
        self.prog_transitions = self.load_data(self.prog_filename)
        self.sum_transition()

        
        # self.clear_rfc_json()
    def sum_transition(self):

        self.rfc_transitions_full = copy.deepcopy(self.rfc_transitions)
        self.prog_transitions_full = copy.deepcopy(self.prog_transitions)

        for rfc_tr in self.rfc_transitions:
            rfc_tr.pop("action")
        for prog_tr in self.prog_transitions:
            if "action" in prog_tr.keys():
                prog_tr.pop("action")

    def clear_rfc_json(self):

        tmp_rfc = []
        old_rfc_st ={}
        # self.prog_transitions = self.prog_transitions[1:]
        # self.prog_transitions =
        for rfc_st in self.prog_transitions:
            if rfc_st == old_rfc_st:
                continue
            if rfc_st["dest"] != "":
                tmp_rfc.append(rfc_st)
                old_rfc_st = rfc_st
        self.prog_transitions = copy.deepcopy(tmp_rfc[1:])
        # print(len(self.prog_transitions))

        # print(self.prog_transitions)
        

        


    def parse_config(self, filename):
      
       
        with open(filename, 'r') as f:
            json_data = json.load(f)
        
        self.rfc_filename = json_data["RFC_FSM_Data"]
        self.prog_filename = json_data["SUT_FSM_Data"]

        self.rfc_transitions = self.load_data(self.rfc_filename)
        self.prog_transitions = self.load_data(self.prog_filename)

        # print self.rfc_transitions
        # print self.prog_transitions
        self.state_map = json_data["State"]
        # print self.state_map
        # print self.rfc_states

        for st in self.state_map:
            self.rfc_states.append(st["RFC_State"])
            self.prog_states +=st["SUT_State"]
        # print self.rfc_states
        # print self.prog_states  
        self.event_map = json_data["Event"]
        for ev in self.event_map:
            self.rfc_ev.append(ev["RFC_Ev"])
            for e in ev["SUT_Ev"]:
                if e not in self.prog_ev and e != "":
                    self.prog_ev += ev["SUT_Ev"]
      
        self.prog_ev += json_data["Unknown_map_ev"]
        self.unknown_event = json_data["Unknown_map_ev"]
        # print self.rfc_ev, len(self.rfc_ev)
        # print self.prog_ev, len(self.prog_ev)
      
    def load_data(self, filename):
        f = open(filename,"r")
        trans = eval(f.read())
        f.close()
        return trans
        
    def compare_fsm(self, rfc_trans, rfc_event, tmp_event):

        self.gen_fsm_model(rfc_trans)

        # self.full_compare(tmp_event)
        count = self.full_compare_nw(rfc_event, tmp_event)
        return count
        
    def gen_fsm_model(self,rfc_trans):

        self.rfc_model = Matter()
        self.prog_model = Matter()

        self.rfc_machine = Machine(model=self.rfc_model, states=self.rfc_states, transitions=rfc_trans, initial=self.rfc_states[0])
        self.prog_machine = Machine(model=self.prog_model, states=self.prog_states, transitions=self.prog_transitions, initial=self.prog_states[0])
        # print(self.rfc_states)
        # print(self.prog_states)


    def getProgData(self, state, event):
        
        for stmp in self.state_map:
            if stmp["RFC_State"] == state:
                pstate = stmp["SUT_State"]
                break
        for evmp in self.event_map:
            if evmp["RFC_Ev"] == event:
                pevent = evmp["SUT_Ev"]
                break
        return pstate, pevent

    def isequalDstate(self, rstate, pstate):
        flag = False

        for stmp in self.state_map:
            if stmp["RFC_State"] == rstate:
                if pstate in stmp["SUT_State"]:
                    flag = True
                    break
                
        return flag

    def state_change(self, machine, model, src, ev):

        machine.set_state(src)
        
        try:
            model.trigger(ev)
            dest = model.state
            
        except Exception:
            # print "[Warning] state: " +src+" has no event "+ev+"! dropped"
            dest = src
        # print dest
        return dest

    def single_compare(self, pstate, pevent, rds):

        flag = False

        for pev in pevent:

            pds = self.state_change(self.prog_machine, self.prog_model, pstate, pev )
            # print("-----------")
            # print(pstate, pevent, pds)
            

            # if self.isequalDstate(rds, pds):
            if self.map_states[rds]  == pds:
                flag = True
                self.test_prog.append(self.add_state_change(pstate, pev, pds))
            # print pstate, pev, pds
            # break

        return flag

    def err_log(self, state, event, rds, act,tag):
        print("Rule Violation: ")
        if tag == 1:
            print("Rule: ck_bf(state == "+state+" && event == "+ event+", ["+act+", set(state == "+rds+")])")
            # print("[Error] Missing "+state+" ==="+event+"==> "+rds) 
        elif tag == 2:
            print("[Error] Adding "+state+" ==="+event+"==> "+rds) 
        elif tag == 3:
            print( "[Warning] Missing "+state+" ==="+event+"==> "+rds)
        elif tag == 4:
            print( "[Warning] Candidate"+state+" ==="+event+"==> "+rds)
        # print("     Current "+)

    def unknown_event_compare(self, pstate, pevent, rds, rstate, revent):

        print("We can not mapping the rfc event !") 
        self.err_log(rstate, revent,rds,"", 3)
        flag = False

        for ps in pstate:
            for pev in self.unknown_event:
                pds = self.state_change(self.prog_machine, self.prog_model, ps, pev)
                if self.isequalDstate(rds, pds):
                    self.err_log(ps, pev, pds,"", 4)
                    flag = True
                    
        return flag

    def add_state_change(self, src, event, dest):
        schange = {}
        schange["source"] = src
        schange["dest"] = dest
        schange["trigger"] = event
        return copy.deepcopy(schange)
    def show_miss(self):
        count = 0
        for p in self.rfc_transitions:
            if p not in self.test_rfc:
                self.err_log(p["source"], p["trigger"],p["dest"], "", 1)
                count +=1
        print(len(self.rfc_transitions), count) 

    def show_add(self):
        count = 0
        for p in self.prog_transitions:
            if p not in self.test_prog:
                self.err_log(p["source"], p["trigger"],p["dest"], "",2)
                count +=1
        print(len(self.prog_transitions), count) 
    
    def full_compare(self, tmp_event):
        count = 0
        rcount = 0

       
        for rstate in self.rfc_states:
            for revent in self.rfc_ev:
                
                rds = self.state_change(self.rfc_machine, self.rfc_model, rstate, revent)

                # print rstate, revent, rds

                trans_flag = False
                unflag = False
                pstate, pevent = self.getProgData(rstate, revent)
                # pstate = self.map_states[rstate]
                # if revent not in tmp_event.keys():
                #     continue
                # pevent = tmp_event[revent]
                # print (pstate, pevent)
                # if not pevent 
                ps_size = len(pstate)
                pe_size = len(pevent)

                if pe_size == 0:
                    unflag = self.unknown_event_compare(pstate, pevent, rds, rstate, revent)
                    count +=1
                    continue

                if ps_size == 1:
                    trans_flag = self.single_compare(pstate[0], pevent, rds)

                elif ps_size > 1:
                    for ps in pstate:
                        trans_flag = self.single_compare(ps, pevent, rds)
                        if trans_flag:
                            break
                else:
                    print( "something wrong in the pstate mapping!")

                if not trans_flag:
                    pass
                    count +=1
                    # self.err_log(rstate, revent, rds, 1)
                else:
                    rcount +=1
                    self.test_rfc.append(self.add_state_change(rstate, revent, rds))
                    
        # self.show_add()    
        # self.show_miss()   
        # print count, rcount

    def full_compare_nw(self, rfc_event, tmp_event):

        count = 0
        rcount = 0
        # print(tmp_event)

        for rstate in self.rfc_states:
            for revent in rfc_event:
                
                rds = self.state_change(self.rfc_machine, self.rfc_model, rstate, revent)

                # print rstate, revent, rds

                trans_flag = False
                unflag = False
                # pstate, pevent = self.getProgData(rstate, revent)
                pstate = self.map_states[rstate]
                if revent not in tmp_event.keys():
                    # self.err_log(rstate, revent, rds, 3)
                    continue
                pevent = tmp_event[revent]
                # print(pstate, pevent)
                # if not pevent 
                # print(rstate, revent, rds)
                # print(pstate, pevent)
                trans_flag = self.single_compare(pstate, pevent, rds)
                if not trans_flag:
                    
                    if rstate != rds:
                        count +=1
                    # print("ok")
                        self.err_log(rstate, revent, rds,self.get_action(rstate, revent,rds), 1)

                else:
                    rcount +=1
                    act_flag, pe = self.compare_action(rstate, revent, pstate, pevent)

                    if not act_flag:
                        self.err_log(rstate, revent, rds, self.get_action(rstate, revent,rds), 1)
                        print("[ERROR] UnImpl action "+ pe)
                        print("-------------")
                        count +=1
                    
                    self.test_rfc.append(self.add_state_change(rstate, revent, rds))
                # print("------------------")
        return count
        
    def get_action(self, rs, re, rds):
        if "Event" in re:
            rev = self.min_rfc_event[re]
        for rfc_tr in self.rfc_transitions_full:
            for ee in rev:
                
                if rfc_tr["source"] == rs and rfc_tr["trigger"] == ee:
                    if rfc_tr["action"]:

                        raction = rfc_tr["action"]
                        break
        return raction[0]
            
    def compare_action(self, rs, re, ps, pe):
        raction = []
        paction = []
        rev = []


        if "Event" in re:
            rev = self.min_rfc_event[re]
        for rfc_tr in self.rfc_transitions_full:
            
            for ee in rev:
                
                if rfc_tr["source"] == rs and rfc_tr["trigger"] == ee:
                    if rfc_tr["action"]:

                        raction = rfc_tr["action"]
                        break
        if not raction:
            return True, "NONE"

        for pro_tr in self.prog_transitions_full:
            
            if pro_tr["source"] == ps and pro_tr["trigger"] == pe:
                if "action" in pro_tr.keys():
                    paction = pro_tr[action]
                else:
                    return False, pe[0]
        if len(raction) == len(paction):
            return True, "NONE"
        else:
            return False, pe[0]
    def getedge(self, graph):

        in_edge={}
        out_edge={}

        for tr in graph:
            src = tr["source"]
            dest = tr["dest"]
            if src != dest:
            
                if src in out_edge.keys():
                    out_edge[src] +=1
                else:
                    out_edge[src] = 1

                if dest in in_edge.keys():
                    in_edge[dest] +=1
                else:
                    in_edge[dest] = 1 
        


        out_edge = sorted(out_edge.items(),key = lambda x:x[1],reverse = True)
        in_edge = sorted(in_edge.items(),key = lambda x:x[1],reverse = True)
        # print ("out")
        # print (out_edge)
        # print ("in")
        # print (in_edge)
        return out_edge, in_edge


        pass
    def get_out_state(self,translist, init_state):

        prog_state=[]
        # rfc_state =[]
        # print(init_state)
        # self.translist

        for s in translist:
            # print(s["source"])
            if s["source"] == init_state:
                # print(s["dest"])
                if s["dest"] == s["source"]:
                    continue
                    
                if s["dest"] not in prog_state:
                    prog_state.append(s["dest"])
        # print(prog_state)
        return prog_state
        pass
    def get_in_state(self, translist, init_state):

        prog_state =[]

        for s in translist:
            if s["dest"] == init_state:
                if s["dest"] == s["source"]:
                    continue
                if s["source"] not in prog_state:
                    prog_state.append(s["source"])
        # print(prog_state)
        return prog_state
        
    def get_out_edge(self, translist):

        out_edge_state={}

        for chstate in translist:
            src = chstate["source"]
            dest = chstate["dest"]
            if src != dest:
                if src in out_edge_state.keys():
                    if dest not in out_edge_state[src]:
                        out_edge_state[src].append(dest)
                else:
                    out_edge_state[src]=[dest]
            
        return out_edge_state

    def static_edge(self, translist):

        state_edge_count = {}


        for tran in translist:
            src = tran["source"]
            dest = tran["dest"]
            if src == dest:
                continue
            sdstate = src+"_"+dest
            if sdstate in state_edge_count.keys():
                state_edge_count[sdstate].append(tran["trigger"])
            else:
                state_edge_count[sdstate]= [tran["trigger"]]
        return state_edge_count
        # print(state_edge_count)  
            
    def map_event_one(self, rfc, prog):

        # print("=================")
        # print(self.map_states)
        for state, value in prog.items():

            p = state.split("_")
            psrc = p[0]
            pdest = p[1]
           
            rsrc = [k for k,v in self.map_states.items() if v == psrc]
            rdest = [k for k,v in self.map_states.items() if v == pdest]
            r = rsrc[0]+"_"+rdest[0]

            if len(value) == 1:
                # print(r, state)
                if r in rfc.keys():
                    # print(rfc[r], prog[state][0])

                    if prog[state][0] not in self.map_events.keys():
                        self.map_events[prog[state][0]] = []
                        self.certain_event.append(prog[state][0])

                    for rr in rfc[r]:
                        if rr not in self.map_events[prog[state][0]]:
                            self.map_events[prog[state][0]].append(rr)
                            
                    # print("-------")



    def remove_transitions(self, trans, org_state, nw_state):

        for i in range(0, len(trans)):
            if trans[i]["source"]  == org_state:
                trans[i] = ''
            elif trans[i]["dest"] == org_state:
                trans[i]["dest"] =  nw_state

        trans = [x for x in trans if x!='']
        return trans
    

    def map_transitions(self, trans , state_map, event_map):

        tmp_trans = copy.deepcopy(trans)

        if state_map:

            nw_state = {v:k for k, v in state_map.items()}
        
            for i in range(0, len(tmp_trans)):

                src = tmp_trans[i]["source"]
                dest = tmp_trans[i]["dest"]

                tmp_trans[i]["source"] = nw_state[src]
                tmp_trans[i]["dest"] = nw_state[dest]
        return tmp_trans



    def map_state(self):

        rm_state=[]

        if len(self.rfc_states)  <= len(self.prog_states):
            for i in range(0, len(self.rfc_states)):
                self.map_states[self.rfc_states[i]] = self.prog_states[i]

            if len(self.prog_states)> len(self.rfc_states):

                for i in range(len(self.rfc_states), len(self.prog_states)):
                    # print(self.prog_states[i])
                    state = self.prog_states[i]

                    # print(self.prog_transitions)

                    ous = self.get_out_state(self.prog_transitions, state)
                    ins = self.get_in_state(self.prog_transitions, state)
                    

                    if len(ins) == 1 and len(ous) == 1:
                        # print(state, ous[0])
                        rm_state.append(state)
                        # self.prog_states.remove(state)
                        self.prog_transitions = self.remove_transitions(self.prog_transitions, state, ous[0])
                        # print(self.prog_transitions)
                        
                        
                    elif len(ins) == 0 and len(ous) == 0:
                        # self.prog_states.remove(state)
                        rm_state.append(state)
                        self.prog_transitions = self.remove_transitions(self.prog_transitions, state, "")
            for rs in rm_state:
                self.prog_states.remove(rs)

            return 1
            
        else:
            print(len(self.rfc_states), len(self.prog_states))
            print("The prog state is less than the rfc state, please check!")
            return 0




    def get_src_dest(self, trans):

        event_node ={}
        for tran in trans:
            ev = tran["trigger"]
            src = tran["source"]
            dest = tran["dest"]

            if ev  not in event_node.keys():
                event_node[ev]=[]

            if src != dest:
                event_node[ev].append((src, dest))
            
            
        return event_node
            
    def isequalpair(self, plist1, plist2):
        flag = True

        if len(plist1) != len(plist2):
            return False
        for i in plist1:
            if i not in plist2:
                flag = False
                break
        return flag 

    def pred_state(self):
        self.rfc_states = self.get_state_from_fsm(self.rfc_transitions)
        
        self.prog_states = self.get_state_from_fsm(self.prog_transitions)
        self.prog_states = sorted(list(map(int, self.prog_states)))
        self.prog_states = [str(x) for x in self.prog_states]
        
        
        # print(self.rfc_states, self.prog_states)
        # Get the number of the out and in edge  of each state
        rout_edge, rin_edge =self.getedge(self.rfc_transitions)
        pout_edge, pin_edge = self.getedge(self.prog_transitions)

        # get the initial state
        self.initial_rfc_state = rin_edge[0][0]
        self.initial_prog_state = pin_edge[0][0]

        # print(self.initial_rfc_state, self.initial_prog_state)
        # print("============")

        if self.initial_prog_state == self.prog_states[0]:
            # print("Initial state right", self.initial_prog_state)
        
            self.map_states[self.initial_rfc_state] = self.initial_prog_state
        
        # map state:
        
        self.map_state()
        # print(self.prog_transitions)


        rs_edge = self.static_edge(self.rfc_transitions)
        ps_edge = self.static_edge(self.prog_transitions)
        # print(rs_edge)
        # for k, v in rs_edge.items():
        #     print(k, len(v))
        # print(ps_edge)
        # for k, v in ps_edge.items():
        #     print(k, len(v))
        self.map_event_one(rs_edge, ps_edge)


        # change the prog state to the rfc state
        self.map_transitions(self.prog_transitions, self.map_states, [])  
        revent = self.get_src_dest(self.rfc_transitions)
        pevent = self.get_src_dest(self.prog_transitions)

        # for k, v in revent.items():
        #     print(k)
        #     for vv in v:
        #         print(vv) 
       
        # for k, v in pevent.items():
        #     print(k)
        #     for vv in v:
        #         print(vv)  
        # print("-------------")   

        for k, v in pevent.items():
            if k in self.map_events.keys():
                continue
            # print(k)
            self.map_events[k]=[]
            for kk, vv in revent.items():
                if self.isequalpair(v, vv):
                    print (kk)
                    self.map_events[k].append(kk)
            # print ("====")
                
        # print(self.map_events)    
      
        # get the next state of the initail state
        # self.get_out_state(self.rfc_transitions, self.initial_rfc_state)
        # self.get_out_state(self.prog_transitions, self.initial_prog_state)
       
        # get the state which has only one dest state

        # rout_edge_state = self.get_out_edge(self.rfc_transitions)
        # pout_edge_state = self.get_out_edge(self.prog_transitions)
        # print("============")
        # for k , v in rout_edge_state.items():
        #     print(k, v, len(v))
        # for k,v in pout_edge_state.items():
        #     print(k, v, len(v))
    def minimize_rfc_transitions(self):
        
        revent = self.get_src_dest(self.rfc_transitions)
        revent1 = copy.deepcopy(revent)
        min_event = {}
        has_equal_event=[]

        for k, v  in revent.items():
            min_event[k]=[]

            if k  in has_equal_event:
                continue

            for kk, vv in revent1.items():

                if k == kk:
                    continue
                if self.isequalpair(v, vv):
                    has_equal_event.append(kk)
                    min_event[k].append(kk)


        # print(has_equal_event)
        count = 0
        self.rfc_ev_min = copy.deepcopy(self.rfc_ev)
        # Get the same transtion event   
        for k, v in min_event.items():
            # print(k , v)

            if v:
                vv = copy.deepcopy(v)

                vv.append(k)
                
                self.min_rfc_event["Event_"+str(count)] = copy.deepcopy(vv)
                for rv in vv:
                    self.rfc_ev_min.remove(rv)
                count +=1
        # print("MIN RFC event")
        # print(self.min_rfc_event)

        if not self.min_rfc_event:
            return False

        self.rfc_ev_min += self.min_rfc_event.keys()

        # self.min_rfc_transitions = copy.deepcopy(self.rfc_transitions)
        
        for i  in range(0, len(self.rfc_transitions)):
            flag = False
            
            ev = self.rfc_transitions[i]["trigger"]

            for k, v in self.min_rfc_event.items():

                if ev in v and ev != v[0]:
                    # print(ev)
                    flag = True
                    break

            if not flag:
                # print(self.rfc_transitions[i])
                self.min_rfc_transitions.append(self.rfc_transitions[i])
                    # self.min_rfc_transitions[i]["trigger"] = k
        # print(self.min_rfc_transitions) 


        for i in range(0, len(self.min_rfc_transitions)):
            ev = self.min_rfc_transitions[i]["trigger"]
            for k, v in self.min_rfc_event.items():
                if ev in v:
                    self.min_rfc_transitions[i]["trigger"] = k

        # print(len(self.min_rfc_transitions))
        return True

    def get_state_from_fsm(self, fsm):
        state_list = []
        for chs in fsm:
            src = chs["source"]
            if src == "":
                continue
            
            if src not in state_list:
                state_list.append(src)
        for chs in fsm:
            dest = chs["dest"]
            if dest == "":
                continue
            if dest not in state_list:
                state_list.append(dest) 
        return state_list
    def get_event_from_fsm(self, fsm):

        event_list = []

        for chs in fsm:
            ev = chs["trigger"]
            if ev == "":
                continue
            if ev not in event_list:
                event_list.append(ev)
        return event_list

    def gen_edge(self, fsm, G):

        out_edge = self.get_out_edge(fsm)

        for src, dests in out_edge.items():
            for dest in dests:
                G.add_edge(src, dest)     
               

    # def gen_graph(self):

        self.rfc_states = self.get_state_from_fsm(self.rfc_transitions)
        self.prog_states = self.get_state_from_fsm(self.prog_transitions)

        RG = nx.DiGraph()
        PG = nx.DiGraph()
        RG.add_nodes_from(self.rfc_states)
        PG.add_nodes_from(self.prog_states)

        print(RG.nodes, RG.number_of_nodes())
        print(PG.nodes, PG.number_of_nodes())

        self.gen_edge(self.rfc_transitions, RG)
        self.gen_edge(self.prog_transitions, PG)

        print(RG.edges, RG.number_of_edges())
        print(PG.edges, PG.number_of_edges())
        
        print("isomorphis ? ======== ")
        DiGM = isomorphism.DiGraphMatcher(RG, PG)
        print(DiGM.is_isomorphic())
        print(DiGM.subgraph_is_isomorphic())
        print(len(list(DiGM.subgraph_isomorphisms_iter())))
        print(len(list(DiGM.subgraph_monomorphisms_iter())))
        print(DiGM.mapping)

        DiGM1 = isomorphism.DiGraphMatcher(PG, RG)
        print(DiGM1.is_isomorphic())
        print(DiGM1.subgraph_is_isomorphic())
        print(len(list(DiGM1.subgraph_isomorphisms_iter())))
        print(len(list(DiGM1.subgraph_monomorphisms_iter())))
        print(DiGM1.mapping)
    
    def gen_check_state(self):
        self.rfc_states = self.get_state_from_fsm(self.rfc_transitions)
        
        self.prog_states = self.get_state_from_fsm(self.prog_transitions)
        self.prog_states = sorted(list(map(int, self.prog_states)))
        self.prog_states = [str(x) for x in self.prog_states]
        # print(self.rfc_states, self.prog_states)

    def gen_check_ev(self):

        self.rfc_ev = self.get_event_from_fsm(self.rfc_transitions)
        self.prog_ev = self.get_event_from_fsm(self.prog_transitions)
        # print(self.rfc_ev , self.prog_ev)

    def gen_initial_state(self):
        rout_edge, rin_edge =self.getedge(self.rfc_transitions)
        pout_edge, pin_edge = self.getedge(self.prog_transitions)

        # get the initial state
        self.initial_rfc_state = rin_edge[0][0]
        self.initial_prog_state = pin_edge[0][0]
        # print("initial state")
        # print(self.initial_rfc_state, self.initial_prog_state)
        # print("============")

        self.map_states[self.initial_rfc_state]  = self.initial_prog_state
    
    def mp_state(self):
        rm_state=[]


        for i in self.rfc_states:

            ous = self.get_out_state(self.rfc_transitions, i)
            ins = self.get_in_state(self.rfc_transitions,i)
            self.rstate_inout_state[i]=[len(ous),len(ins)]
        #     print(i, ous, ins)
        # print("====")
        if len(self.rfc_states)  <= len(self.prog_states):

            for  state in self.prog_states:
                ous = self.get_out_state(self.prog_transitions, state)
                ins = self.get_in_state(self.prog_transitions, state)

                # print(state, ous, ins)

                if len(ins) == 0 and len(ous) == 0:
                    rm_state.append(state)
                    self.prog_transitions = self.remove_transitions(self.prog_transitions, state, "")

                if len(ins)  == 1 and len(ous) == 1:

                    edge_num = self.static_edge(self.prog_transitions)
                    # print(edge_num)

                    if edge_num[state+"_"+ous[0]] == edge_num[ins[0]+"_"+state]:

                    # if ous[0] == self.initial_prog_state:
                    #     continue
                        rm_state.append(state)
                        
                        # self.prog_states.remove(state)
                        self.prog_transitions = self.remove_transitions(self.prog_transitions, state, ous[0])

            for rs in rm_state:
                self.prog_states.remove(rs)
            for ps in self.prog_states:
                ous = self.get_out_state(self.prog_transitions, state)
                ins = self.get_in_state(self.prog_transitions, state)
                self.pstate_inout_state[ps] = [len(ous),len(ins)]
            # print(self.prog_states)
           
        else:
            print("The prog state is less than the rfc state, please check!")

    def is_inout_state_equal(self, rstate, pstates):

        in_out = self.rstate_inout_state[rstate]
        ins = in_out[1]
        outs = in_out[0]

        first_cand=[]

        for ps in pstates:
            pins = self.pstate_inout_state[ps][1]
            pouts = self.pstate_inout_state[ps][0]

            if ins == pins and outs == pouts:
                first_cand.append(ps)
        return first_cand

    def greed_state(self, rfc_state, prog_state):

        rs = self.get_out_state(self.rfc_transitions, rfc_state )
        
        ps = self.get_out_state(self.prog_transitions, prog_state)

        # print(rfc_state, rs)
        # print(prog_state, ps)
        flag = True

        # print("=========++++++++++++")

        
        for i in range(0, len(rs)):
            if rs[i] not in self.map_states.keys():
                # print(rs[i])
                # print(ps)
                first_cand = self.is_inout_state_equal(rfc_state, ps)

                for j in range(0, len(ps)):
                    count = 0
                    # print (ps[j])
                    if ps[j]  not in self.map_states.values():
                        count +=1
                        # print(rs[i], ps[j])
                        self.map_states[rs[i]] = ps[j]
                        # print(self.map_states)
                        # print("--")
                        flag = self.greed_state(rs[i], ps[j])
                        if flag == False:
                            break
                        else:
                            break
                    # for the len(rs) > len(ps) and there is no new ps can mapping with the rs
                    if count == 0:   
                        flag = False
        # print("has finished")            
        flag == True
        return flag

    def map_event_equal_state(self, revent, pevent):

        for k, v in pevent.items():
            if k in self.map_events.keys():
                continue
            # print(k)
            self.map_events[k]=[]
            for kk, vv in revent.items():
                
                if self.isequalpair(v, vv):
                    # print (kk)
                    self.map_events[k].append(kk)

                    if k not in self.certain_event:
                        self.certain_event.append(k)
            # print ("====")
                
        # print(self.map_events)  

    def map_certain_event(self):
        # rs_edge = self.static_edge(self.rfc_transitions)
        if self.has_min:
            rs_edge = self.static_edge(self.min_rfc_transitions)
        else:
            rs_edge = self.static_edge(self.rfc_transitions)
        ps_edge = self.static_edge(self.prog_transitions)

        # print(rs_edge)
        # for k, v in rs_edge.items():
        #     print(k, len(v))
        # print(ps_edge)
        # for k, v in ps_edge.items():
        #     print(k, len(v))

        # mapping  A - pevents -> B   the number of pevents is 1 
        # print(self.prog_transitions)
        self.map_event_one(rs_edge, ps_edge)
        tmp_prog_trans = self.map_transitions(self.prog_transitions, self.map_states, [])  


        # print(self.prog_transitions)

        # revent = self.get_src_dest(self.rfc_transitions)
        if self.has_min:
            revent = self.get_src_dest(self.min_rfc_transitions)
        else:
            revent = self.get_src_dest(self.rfc_transitions)
        pevent = self.get_src_dest(tmp_prog_trans)
        # pevent = self.get_src_dest(self.prog_transitions)

        # for k, v in revent.items():
        #     print(k)
        #     for vv in v:
        #         print(vv) 
       
        # for k, v in pevent.items():
        #     print(k)
        #     for vv in v:
        #         print(vv)  
        # print("-------------")  

        # mapping the event transition state is the same

        self.map_event_equal_state(revent, pevent)

    def greed_event(self, nohit_revent):

        nohit_pevent = list(set(self.prog_ev)-set(self.certain_event))

        tmp_event = copy.deepcopy(self.map_events)
        use_event = []
        # print(nohit_pevent)
        # print(nohit_revent)

        for pev in nohit_pevent:

            if pev not in self.use_event_map.keys():
                self.use_event_map[pev] =[]

            revs = tmp_event[pev]
            # print(pev, revs)
            if not revs:
                # print(1)
                for rev in nohit_revent:
                    if rev not in use_event and rev not in self.use_event_map[pev]:
                        tmp_event[pev] = [rev]
                        use_event.append(rev)
                        self.use_event_map[pev].append(rev)
                        break

        # print(tmp_event)
        return tmp_event
    def p2revmap(self, map_event):

        rmap={}

        for pev, revs in map_event.items():
            for rev in revs:

                if rev not in rmap.keys():
                    rmap[rev] = []
                rmap[rev].append(pev)

        return rmap


    def get_premuations_event(self, nohit_revent, nohitP):

        premu = []

        comb_ev = list(itertools.combinations_with_replacement(nohit_revent, nohitP))

        for com in comb_ev:
            
            premu_ev = list(itertools.permutations(com))


            premu +=list(set(premu_ev))

        return premu

        pass

    def mul_fsm_check(self):

        # print(self.certain_event)

        # tmp_event = copy.copy(self.map_events)

        # print(tmp_event)
        
        rhit_event = []

        for pev, revs in self.map_events.items():

            for r in revs:
                if r not in rhit_event:
                    rhit_event.append(r)
                continue
        pass
        # print (rhit_event)
        # print(self.certain_event)
        # print(self.rfc_ev_min)
        # print(self.min_rfc_event)

        # print(hit_event)
        # print("-------")
        # print(list(set(self.rfc_ev) - set(hit_event)))
        # use_event_map ={}
        nohitP = len(self.prog_ev) - len(self.certain_event)
        if self.has_min:
            nohitR = len(self.rfc_ev_min) - len(rhit_event)
        else:
            nohitR = len(self.rfc_ev) - len(rhit_event)
    

        # print (nohitP, nohitR)
        # i = 0

        # while i < nohitR:
        if self.has_min:

            nohit_revent = list(set(self.rfc_ev_min) - set(rhit_event))
        else:
            nohit_revent = list(set(self.rfc_ev) - set(rhit_event))
        nohit_pevent = list(set(self.prog_ev)-set(self.certain_event))
        # print(nohit_revent)
        comb = self.get_premuations_event(nohit_revent, nohitP)

        # print(comb)
        # print(len(comb))

        tmp_event = copy.deepcopy(self.map_events)
        count = 0
        if self.has_min:
            min = len(self.min_rfc_transitions)
        else:
            min = len(self.rfc_transitions)
        # print(self.min_rfc_transitions)
        for c in comb:

            for i in range(0, len(nohit_pevent)):
                
                pev = nohit_pevent[i]
                tmp_event[pev] = [c[i]]
            
            # print(tmp_event)
            
            rp_event = self.p2revmap(tmp_event)
           
            # print("Roud: ", count)
            # print("Not hit rfc event: ")
            # print(list(set(nohit_revent) - set(c)))
            # print("Mapping:")
            # print(rp_event)
            # print(tmp_event)
            # print(self.rfc_ev_min)
            if self.has_min:
                # print("min")
                # print(self.min_rfc_transitions)
                # print(self.rfc_ev_min)
                Err = self.compare_fsm(self.min_rfc_transitions, self.rfc_ev_min, rp_event)
            else:
                Err = self.compare_fsm(self.rfc_transitions, self.rfc_ev, rp_event)
            print("Inconsistency bugs: "+str(Err))
            

            count +=1 

            if min > Err:
                min = Err

            # print("---------------------")
        
        # print("The most similiar FSM missing:", min)


    def check_fsm(self):

        self.gen_check_state()
        self.gen_check_ev()
        self.clear_rfc_json()

        # get the initial state ======================
        self.gen_initial_state()

        # mapping state ===================
        self.mp_state()
        # print(self.map_states)

        if len(self.rfc_states)  == len(self.prog_states):
            for i in range(0, len(self.rfc_states)):
                self.map_states[self.rfc_states[i]] = self.prog_states[i]

        else:   

            res = self.greed_state(self.initial_rfc_state, self.initial_prog_state)
        # print("State map: ")
        # print(self.map_states)

        # self.map_states={'Active 2': '8', 'PASSIVE': '1', 'Active 0': '2', 'Active 3': '16', 'Active 1': '4'}
        # print(self.map_states)
        
        if not self.map_states:
            sys.exit()
        # print(self.map_states)


        # start event and modal check ===========================
        self.has_min = self.minimize_rfc_transitions()
        # print(self.has_min)
        # print("min")
        # print(self.map_states)
        self.map_certain_event()
        # print("MAP event: ")
        # print(self.map_events)
        
        
        # # # print(self.prog_transitions) 
        self.mul_fsm_check()


if __name__ == "__main__":
    print("----------------------------------")

    print("The result of state transistion in "+sys.argv[1])
    time_start = time.time()
    fsmcp = Compare()


  
    fsmcp.parse_config1(sys.argv[1], sys.argv[2])
    
    
    fsmcp.check_fsm()
   
    # time_end = time.time()
    # time_sum = time_end - time_start
    # print("Total Time: ")
    # print(time_sum)
