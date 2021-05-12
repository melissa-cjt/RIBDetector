import sys
sys.path.append('../tool/RFCextract')


from extract_err import *
from extract_pkt import *
import sys


if __name__ == '__main__':


    rfc_cfg_fname = "rfc_config.xml"

    '''
    pakcet meta-info and rule extraction
    '''
 
    rfc_pkt = RFC_PKT_Rules_Extract()
    rfc_pkt.parse_config_file(rfc_cfg_fname)
    rfc_pkt.packet_nw()
    rfc_pkt.get_picture_bw_nw()
   
    rfc_pkt.pkt_format_rule()
    rfc_pkt.write_key_words(rfc_pkt.section_file)


    '''
    Error handling rule extraction
    '''
    rfc_ext = RFC_ERR_Rules_Extract()
    rfc_ext.parse_config_file(rfc_cfg_fname)

    rfc_ext.err_handling_nw()
    rfc_ext.parse_err_meta()
    rfc_ext.write_key_words(rfc_ext.section_file)
    rfc_ext.parse_err_handling_nw()



