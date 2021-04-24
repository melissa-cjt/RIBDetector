# Description

RIBDetector is a tool which performs inconsistency bug detection in protocol implementations. It supports the following functionality:

1. Given a series of RFC documents and a pre-written configuration file about their writing style, it can automatically extract rules about packet format, state machine and error handling from the documents.

2. It can identify the rule-specified operations in corresponding protocol implementations and detect inconsistency bug based on the extracted rules.

Currently, RIBDetector supports detection on C/C++ protocol implementations only.

# File structure
The most important folders in RIBDetector's root directory are:

1. 'tool', directory containing the Python scripts for rule extraction and the LLVM pass for bug detection.

2. 'input', directory containing examples of configuration file and RFC documents. 

	i. 'rfc_config.xml', example of configuration file describing the format of specific keywords and meta-info in BGP, OSPF and other routing protocols. Users can modify the file if needed.
   
    ii. 'RFC4271.txt', the draft Standard RFC of BGP. 

3. 'output', directory containing examples of extracted rules, results of rule-specified operation identification and bug detection.

	i.  'rules/meta-info.json', examples of machine readable rules/meta-info extracted from RFC documents under the input directory, which will be used as input of operation identification and bug detection.
	
    ii. '' 'packet/fsm/error.json', examples of structures or function arguments identified by RIBDetector in source code implememtations, which will be further used to investigate rule-specified operations and detect inconsistency bugs.
   
    iii. 'bug_report', example of bug report.

# How to use

To use RIBDetector, it is necessary to perform the following steps:

1. Ensure pre-requisites are met

2. Use RIBDetector to extract RFC rules

3. Use WLLVM to compile the under-considering protocol implementation into one .bc file

4. Use RIBDetector to perform inconsistency bug detection on the file

## Ensuing pre-requisites

RIBDetector has been tested on Ubuntu 16.04. It should work on any recent Linux distribution. Support for other platform has not been tested. In a nutshell, the advised pre-requisites are:
* Ubuntu 16.04 
* Pyhton2.7, NLTK 
* LLVM 4.0, Clang 4.0
* WLLVM
* Z3 Solver 4.8.10

## RFC Rule Extraction

To extract rules from RFC documents in the 'input' directory. run:

```
python extract.py
```

Examples of rules and meta-info extracted are as follows:

`rule.json`:
```
Rules:[ // rule: (hold >0 && hold <3) ? set(errcode, [2,6]) : ε
    {
        "error_code": [2, 6],    // set(errcode, [2,6])
        "type": 3,               //1: single rule, 3: multiple rules
        "connect":[1],           // 1: '&&' 2: '||'
        "keyword": "hold" 
        "rfc_conds":[{
            "rfc_cond": [
                {
                    "lhs": "x",
                    "predicate": 34, // hold >0
                    "rhs": "0"
                },
                {
                    "lhs":"x",
                    "predicate": 36, // hold <3
                    "rhs":"3"
                }
            ],
            
        }]
        
    },
    ....
]
```

`meta-info.json`:
```
"meta-infos": [
    [1, 2, 3, 4, 5, 6]/*error code*/,
    [1, 2, 3, 4, 5, 6, 8, 9, 10, 11]/*error subcode*/
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
Suppose the target protocol implementation is complied into a .bc file named bgp.bc, to perform inconsistency bug detection on the implementation, run:

```
opt -load LLVMRFC.so -Identify <bgp.bc> /dev/null
opt -load LLVMRFC.so <detection_option> <bgp.bc> /dev/null  

detection_option:
-PktDetect: detect violation of packet rules.
-FSMDetect: detect violation of state machine rules.
-ErrDetect: detect violation of error handling rules.
```

Examples of key structures and function arguments identified by our  tool are as follows:
`error.json`:
```
"Function":[{"arg_pos":[1,2],"name":"rde_update_err"},{"arg_pos":[1,2],"name":"session_notification"}]
```

Example of error handling rule violation detection:
`bug_report`:
```
Total rule number: 25  // Number of rules extracted from RFC 4271 about error handling
Identified error handling operations: 61   // Number of error handling rule-specified operations 
                                           // identified in the source code implementation
===============
Not hit rfc rule op: // The uncovered errorcode and errorsubcode
3 8 
Implemented rules/Total rules: 23/25  // The pecentage of rules covered by the implemetation
===============
Rules voilation:
Find operation: session_notification errorcode: 2 errorsubcode: 3 in function: parse_open 
RFC conds: x  32  0 && x  32  y 
Impl Conds: if.end49 ntohl(bgpid) 32 0    
[ERROR] Impl Conds do not comply with RFC Conds 
==========
```


