import sys
sys.path.append('../tool/RFCextract')


from extract_err import *
from extract_pkt import *
from extract_seq import *
import time


if __name__ == '__main__':

    rfc_cfg_fname = sys.argv[1]
    '''
    pakcet meta-info and rule extraction
    '''
 
    rfc_pkt = RFC_PKT_Rules_Extract()
    rfc_pkt.parse_config_file_json(rfc_cfg_fname)
    rfc_pkt.packet_json_nw()
    rfc_pkt.get_meta_special()
    rfc_pkt.get_pkt_rules()


    '''
    Error handling rule extraction
    '''
    rfc_ext = RFC_ERR_Rules_Extract()
    rfc_ext.parse_config_file_json(rfc_cfg_fname)

    rfc_ext.err_handling_json_nw(rfc_pkt.section_file)
    rfc_ext.parse_err_handling_nw_v2()


    '''
    FSM rule extraction
    '''
    rfc_fsm = RFC_Seq_Rules_Extract()
    rfc_fsm.parse_config_file_json(rfc_cfg_fname)
    rfc_fsm.fsm_json(rfc_pkt.section_file)
    rfc_fsm.get_event_state_meta()
    rfc_fsm.fsm_extract()


