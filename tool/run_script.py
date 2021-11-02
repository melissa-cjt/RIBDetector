import sys
import argparse
import os
import re
import json

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="your script description") 
    parser.add_argument('--bitcode', '-bc', type=str, required = True, help='.bc file of the implementation')
    parser.add_argument('--configuration', '-config', type=str,  required = True, help='configuration file of the Rule extractor of the protocol')

    args = parser.parse_args()

    if args.bitcode:
        bc_path = args.bitcode
        # print(bc_path)
    if args.configuration:
        config_path = args.configuration
        # print(config_path)
        f = open(config_path,'r')
        json_data = json.load(f)
        
        config_path = config_path.replace("../input/","")

        if "file" in json_data["packet_format"].keys():
            raw_path = json_data["packet_format"]["file"]["rule"]
            raw_path = raw_path.replace("tmp/","").replace("txt","json")
        else:
            raw_path = "pktrule_" + json_data["filename"].replace("doc/","").replace("txt","json")

        meta_info_path = "../output/result_of_extractor/meta-info-"+raw_path
        
        errrule_info_path = "../output/result_of_extractor/errrule-"+raw_path

        Identify_errule = "../output/result_of_Identify/Identify_"+raw_path

        fsm_rule = "../output/result_of_extractor/fsmrule-"+raw_path
        fsm_prule = "../output/result_of_Identify/fsmprule.json"
        
        # pktrul_info_path = "../output/result_of_extractor/pktrule-"+meta_info_path
        # fsmrule_info_path = "../output/result_of_extractor/fsmrule-"+meta_info_path
        


    cmd1 ="cd ../input && python extract.py "+config_path
    print("step 1: run Rule Extractor  ...")
    print("Cmd: ",cmd1)
    print(os.system(cmd1))
    # print(os.system("pwd"))

    cmd2 = "./rfc --Identify "+bc_path+" "+meta_info_path
    print("step 2: run Identifier  ...")
    print("Cmd:", cmd2)
    print(os.system(cmd2))



    cmd3 = "./rfc --ErrDetect "+bc_path+" "+Identify_errule+" "+errrule_info_path+" > ../output/inconsistency_bug/bug_report_"+raw_path.replace(".json",".txt")+" 2>&1"
    print("step3: Error Handling vailation detection ...")
    print("Cmd:", cmd3)
    # print("--------------------------------")
    # print("The result of the Error Hanlding detection in RFC "+ json_data["filename"])
    print(os.system(cmd3))

    cmd4 = "./rfc --FSMDetect "+bc_path+" "+Identify_errule
    print("step4: State Machine vailation detection ...")
    # print("Cmd:", cmd4)
   

    cmd5 ="python RFCextract/fsm_compare.py "+fsm_rule+ " "+fsm_prule+" >>  ../output/inconsistency_bug/bug_report_"+raw_path.replace(".json",".txt")+" 2>&1"
    print("Cmd:", cmd4)
    print("Cmd:", cmd5)
    print(os.system(cmd4))
    print(os.system(cmd5))
    
    # identify_path = "../output/res_of_identify/Identify.json"

    # cmd3 = "rfc --ErrDetect "+ bc_path+" "+identify_path
    




   