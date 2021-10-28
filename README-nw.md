# Description

RIBDetector is a tool which performs inconsistency bug detection in protocol implementations. It supports the following functionality:

1. Given a series of RFC documents and a pre-written configuration file about their writing style, it can semi-automatically extract rules about packet format, state transition and error handling from the documents.

2. It can identify the rule-specified operations in corresponding protocol implementations and detect inconsistency bug based on the extracted rules.

Currently, RIBDetector supports detection on C/C++ protocol implementations only.

# File structure
The most important folders in RIBDetector's root directory are:

1. **'tool'**, directory containing the Python scripts for rule extraction and the LLVM pass for bug detection.

2. **'input'**, directory containing examples of configuration file and RFC documents. 



    i. **'doc/rfcxxx.txt'** contains the RFC document of network protocol. 
    <!-- Also, we provide the documents which has been filter in 'tmp/'. -->

    ii. **'config/rfc_config_xx.json'**, example of configuration file describing the format of specific keywords and meta-info in BGP, OSPF and other routing protocols. Users can modify the file if needed.   

    iii. **'config/detect_config_xx.json'**, example of configuration file describing the type of inconsistency bug detection.

    iv. **'proc/xx.bc'**, example of  .bc file of network protocol implementations complied with LLVM.


3. **'output'**, directory containing examples of extracted rules, results of rule-specified operation identification and bug detection.

	i. **'result_of_extractor/rule-xx.json or meta-info-xx.json'**, examples of machine readable rules/meta-info extracted from RFC documents under the input directory, which will be used as input of operation identification and bug detection.

	
    ii. **'result_of_identify/Iden_xx.json'**, examples of structures or function arguments identified by RIBDetector in source code implememtations, which will be further used to investigate rule-specified operations and detect inconsistency bugs.     
   
    iii. **'inconsistency_bug/bug_report'**, example of bug report.
4. **'run_script'**, directory containing the running script of inconsistency bug detection.
# How to use

To use RIBDetector, it is necessary to perform the following steps:

1. Ensure pre-requisites are met

2. Use RIBDetector to extract RFC rules

3. Use WLLVM to compile the under-considering protocol implementation into one .bc file

4. Use RIBDetector to perform inconsistency bug detection on the file

## Ensuing pre-requisites

RIBDetector has been tested on Ubuntu 16.04. It should work on any recent Linux distribution. Support for other platform has not been tested. In a nutshell, the advised pre-requisites are:
* Ubuntu 16.04 
* Pyhton3.6, NLTK, spacy 
* LLVM 10.0, Clang 10.0
* WLLVM
* Z3 Solver 4.8.10

## Rule Extractor

To extract rules from RFC documents in the 'run_script' directory. run:

```
python extract.py config/rfc_config_xx.json
```
Example of configure file of bgp: rfc_config_bgp.json 
```
{
    "filename": "doc/rfc4271.txt",
    "page": "RFC 4271                         BGP-4                      January 2006",
    "key_words":["maximum message"],
    "packet_format": {
        "packet_pos": 1,  

        "section_start": "4.  Message Formats",
        "section_end": "5.  Path Attributes",
        "pkt_ftype": 1, 
        "filed_format":{
           "rfield":":",
           "haswrap": 1
        },
    },
    "FSM":{
        "section_start": "8.1.2.  Administrative Events",
        "section_end": "9.  UPDATE Message Handling",
        "meta_regx":{
            "state":"   (.*) State:",
            "event":"      Event (.*): (.*)"
        },
        "fsm_regx":{
            "src_state":"   (.*) State:",
            "event":{
                "Single": "Event (\\d+)", 
                "Multi":"\\(Events (.+?)\\)"
            },
            "dest_state":{
                "Unchange":["stays in the (.*) state","remains in the (.*) state"],
                "Change":["changes its state to (.*)\\."]
            }
        }
        
    },
    "Error_Handling":{
        "file":{
            "rule":"tmp/errrule_rfc4271.txt"
        },
        "section_start": "6.1.  Message Header Error Handling",
        "section_end": "6.4.  NOTIFICATION Message Error Handling",
        "Error_code_meta":{
            "error_code":["Error code"],
            "error_subcode":["Message Header Error","OPEN Message Error","UPDATE Message Error"]}
    }
}
```

Examples of rules and meta-info extracted are as follows:

resutl_of_extractor/meta-info-bgp.json
   
```
   "Meta-Info": {
        "Structure_list":{
            "struct_name": "OPEN Message Format",
            "value": [ 8, 16, 16, 32, 8, 0],
            "fieldname": [ "Version", "Autonomous System", "Hold Time", "BGP Identifier", "Opt Parm Len", "Optional Parameters"]
        },
        "Value_list": {
            "state":["Idle", "Connect", "Active", "OpenSent", "OpenConfirm","Established"],
            "event":["ManualStart","ManualStop", ..., "UpdateMsg", "UpdateMsgErr"],
        
    }
    "packect format:"
    "Rules":[ // rule: chk_bf((Hold Time == 0 && Hold Time >=3), use(Hold Time))
        {
            "Cond":[{
                "rfc_cond": [
                    {
                        "lhs": "x",
                        "predicate": 32, // hold time == 0
                        "rhs": "0"
                    },
                    {
                        "lhs":"x",
                        "predicate": 35, // hold time >= 3
                        "rhs":"3"
                    }
                ],
            }]
            "OP": {"USE": "Hold Time"}  // use(Hold Time)
            "type": 3,               //1: single rule, 3: multiple rules
            "connect":[1],           // 1: '&&' 2: '||'
            "structure": {"struct_name": "Open Message Format", "fieldname": "Hold Time"}    
        },
        
    ]
    "FSM"
    "Rules":[ // rule: chk_bf(state == OpenSent && event = UpdateMsg，set(state, Idle))
        { 
            "source": "OpenSent", 
            "event": "UpdateMsg",
            "dest": "Idle"
        },
        
    ]
```


## Compiling Target Implementation

Before performing bug detection, one should compile the target protocol implementation with WLLVM.

```
export LLVM_COMPILER=clang
CC=wllvm CXX=wllvm++  ./configure  CFLAGS="-g -O0"
extract-bc <target_dir> 
```

## Inconsistency Bug Detection 
Suppose the target protocol implementation is complied into a .bc file named bgpd.bc, to perform inconsistency bug detection on the implementation, run:

```
run_script/run-xx.sh 
```
or 
```
USAGE: rfc [options] <input bitcode> <configure file>

  --Identify            - Identify initial scope
  --ErrDetect           - detect violation of error handling rules.
  --FSMDetect           - detect violation of state machine rules.
  --ErrDetect           - detect violation of packet rules.
  
 rfc --Identify proc/bgpd.bc   config/detect_config_bgp.json'

 rfc --PktDetect proc/bgpd.bc  ../result_of_identifier/identify_bgp.json'
 rfc --FSMDetect proc/bgpd.bc  ../result_of_identifier/identify_bgp.json'
 rfc --ErrDetect proc/bgpd.bc  ../result_of_identifier/identify_bgp.json'
```
Example of the detection configure file of bgp protocol: detect_config_bgp.json
```
{
    "meta-info-file": ../result_of_extractor/meta-info-rfc4271.json
    "packet_format": 1,
    "FSM":1,
    "Error Handling":{
        "error_code":["Error code"],
        "error_subcode":["Message Header Error","OPEN Message Error","UPDATE Message Error"]
    }
    "pktrule-file": "../result_of_extractor/pktrule-rfc4271.json"
    "fsmrule-file": "../result_of_extractor/pktrule-rfc4271.json"
    "errrule-file": "../result_of_extractor/errrule-rfc4271.json"
}
```

Examples of key structures and function arguments identified by our  tool are as follows:
`Identify_bgp.json`:
```
{

    "PKT":{
        "pktrule-file": "../result_of_extractor/pktrule-rfc4271.json"
        "structure":[
            "rfc": "BGP Header",
            "impl":"struct.msg_header"
            ],
        }
        
    },
    "FSM":{
        "fsmrule-file": "../result_of_extractor/fsmrule-rfc4271.json"
        "src_state":{
            "structure": "struct.peer", 
            "offset": 17
        },
        "event":[{
            "func":"bgp_fsm",
            "arg":1,
        }]
        "dest_state":[{
            "func":"change_state",
            "arg": 1,
        }]
    },
    "Error":{
        "errrule-file": "../result_of_extractor/errrule-rfc4271.json"
        "Func":[{
            "arg_pos":[1,2],
            "func":"rde_update_err"
        },
        {
            "arg_pos":[1,2],
            "func":"session_notification"
        }]
    }
}

```

Example of error handling rule violation detection:
`bug_report_bgp`:

```
=============
Total RFC Rules:
Operatoin Found: xx
SrcLocs: xx
UnImpl: xx
Inconsistency Bugs: xx
=============
Rule violation:
Rule: chk_bf(BGP Identifier == 0 || BGP Identifier == local BGP Identifer, set(2, 3) )
Locaton: xx.c line xx function xx
Impl Cond: if.end49 ntohl(bgpid) 32 0  
[ERROR] Impl Conds do not comply with RFC Conds
-------------

```
