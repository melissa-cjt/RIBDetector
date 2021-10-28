# Description

RIBDetector is a tool which performs inconsistency bug detection in protocol implementations. It supports the following functionality:

1. Given a series of RFC documents and a pre-written configuration file about their writing style, it can extract rules about packet format, state transition and error handling from the documents.

2. It can identify the rule-specified operations in corresponding protocol implementations and detect inconsistency bug based on the extracted rules.

Currently, RIBDetector supports detection on C/C++ protocol implementations only.

# File structure
The most important folders in RIBDetector's root directory are:

1. **'tool'**, directory containing the Python scripts for rule extraction and the LLVM pass for bug detection.

2. **'input'**, directory containing examples of configuration file and RFC documents. 

    i. **'doc/rfcxxx.txt'** contains the RFC document of network protocol. 
    
    ii. **'config/rfc_config_xx.json'**, example of configuration file describing the format of specific keywords and meta-info in BGP, OSPF and other routing protocols. Users can modify the file if needed.   
    
    iii. **'proc/xx.bc'**, example of  .bc file of network protocol implementations complied with LLVM.


3. **'output'**, directory containing examples of extracted rules, results of rule-specified operation identification and bug detection.

	i. **'result_of_extractor/rule-xx.json or meta-info-xx.json'**: machine readable rules/meta-info extracted from RFC documents under the input directory, which will be used as input of operation identification and bug detection.

	
    ii. **'result_of_identify/Identify_xx.json'**: structures or function arguments identified by RIBDetector in source code implementations, which will be further used to investigate rule-specified operations and detect inconsistency bugs.     
   
    iii. **'inconsistency_bug/bug_report_xx'**: bug report.
# How to use

To use RIBDetector, it is necessary to perform the following steps:

1. Ensure pre-requisites are met

3. Use WLLVM to compile the under-considering protocol implementation into one .bc file

4. Use RIBDetector to perform inconsistency bug detection on the file

## Ensuing pre-requisites

RIBDetector has been tested on Ubuntu 16.04. It should work on any recent Linux distribution. Support for other platform has not been tested. In a nutshell, the advised pre-requisites are:
* Ubuntu 16.04 
* Pyhton3.6, NLTK, spacy 
* LLVM 10.0, Clang 10.0
* WLLVM
* Z3 Solver 4.8.10

## Compiling Target Implementation

Before performing bug detection, one should compile the target protocol implementation with WLLVM.

```
export LLVM_COMPILER=clang
CC=wllvm CXX=wllvm++  ./configure  CFLAGS="-g -O0"
extract-bc <target_dir> 
```

## Run Script

To  perform inconsistency bug detection on the implementation, run:

```
tool/run_script.py -bc <input bitcode> -config <configure file> 
-bc                .bc file of the implementation
-config            configuration file of the Rule extractor of the protocol  

eg: tool/run_script.py -bc proc/openbgpd.bc -config config/rfc_config_bgp.json
```

## Result

**step 1: Rule Extractor**

Examples of rules and meta-info extracted are as follows: `result_of_extractor/meta-info-bgp.json`

```
   "Meta-Info": {
        "Structure_list":{  // packt format
            "struct_name": "OPEN Message Format",
            "value": [ 8, 16, 16, 32, 8, 0],
            "fieldname": [ "Version", "Autonomous System", "Hold Time", "BGP Identifier", "Opt Parm Len", "Optional Parameters"]
        },
        "Value_list": {
            "state":["Idle", "Connect", "Active", "OpenSent", "OpenConfirm","Established"],   // fsm
            "Error code": { "Message Header Error": "1","OPEN Message Error": "2", ..., "Cease": "6"},    //error code      
            "OPEN Message Error": { "Unsupported Version Number": "1", ..., "Unacceptable Hold Time": "6"}    // error subcode
        },
    }
    // packect format:
    "Rules":[ // rule: chk_bf((Hold Time == 0 && Hold Time >=3), use(Hold Time))
        {
            "Cond":[{
                "rfc_cond": [
                    { "lhs": "x", "predicate": 32, "rhs": "0"},  // hold time == 0
                    { "lhs": "x", "predicate": 35, "rhs": "3"} // hold time >= 3 
                ],
            },]
            "OP": {"USE": "Hold Time"}   // use(Hold Time)
            "type": 3,                   //1: single rule, 3: multiple rules
            "connect":[1],               // 1: '&&' 2: '||'
            "structure": {"struct_name": "Open Message Format", "fieldname": "Hold Time"}    
        },
    ]
    // FSM
    "Rules":[ // rule: chk_bf(state == OpenSent && event = UpdateMsg，set(state, Idle))
        {  "source": "OpenSent",  "event": "UpdateMsg", "dest": "Idle" },  
    ]
    // Error Handling
    "Rules":[// rule: chk_bf(version != 4, set(error subcode, 1))]
        {
            "Op": { "SET":(Error subcode, 1)},  //set(error subcode, 1)
            "Cond": [{
                    "rfc_cond": [
                        { "lhs": "x", "predicate": 33,"rhs": "4"} // version != 4
                    ],
                    "connect": [],
                    "type": 1,
                    "fieldname": "version"
                },]
         },
     ]
```

**step 2: Analysis Scope Identifier**

Examples of key structures and function arguments identified by our  tool are as follows: `result_of_identify/Identify_bgp.json`:

```
{
    "PKT":{
        "structure":[
            "rfc": "BGP Header",
            "impl":"struct.msg_header"
            ],
        }
    },
    "FSM":{
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

**step 3: Violation Detector**

Example of error handling rule violation detection:`inconsistency_bug/bug_report_bgp`:

```
=============
#Total RFC Rules: 146 
#Inconsistency Bugs: 3
=============
Rule violation:
Rule: chk_bf(BGP Identifier == 0 || BGP Identifier == local BGP Identifer, set(2, 3) )
Locaton: xx.c line xx function parse_open
[ERROR] Impl Conds do not comply with RFC Conds
-------------
...
```
