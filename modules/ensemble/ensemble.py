# Ensemble module implementation

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import json
import random

class EnsembleModule(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'ensemble'
    description = 'Module to detect infected hosts detection applying ensembling'
    authors = ['Paula Venosa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # To which channels do you want to subscribe? When a message
        # arrives on the channel the module will wakeup
        # The options change, so the last list is on the
        # slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        
        #  This module will be activate when a timewindows finish
        self.c1 = __database__.subscribe('tw_closed')
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # Other systems
            self.timeout = None

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the processes into account
        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')
        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def phase1voting(self,modulesLabels):
        weights = {'test1':1,'test2':3,'test3':1}
        maliciousVotes = 0
        normalVotes = 0
        ensemble_Label = ''
        for classifier, label in modulesLabels.items(): 
            if (label == 'malicious'):
                maliciousVotes = int(maliciousVotes+weights[classifier])
            else:
                normalVotes = int(normalVotes+weights[classifier])
        if (maliciousVotes > normalVotes):
            #print('MALICIOUS WINS THE VOTING')
            #print(maliciousVotes)
            #print(normalVotes)
            ensembleLabel = 'malicious'
        else:
            #print('NORMAL WINS THE VOTING')
            #print(maliciousVotes)
            #print(normalVotes)
            ensembleLabel = 'normal'
        return ensembleLabel
         
###########################Phase 2 functions##########################################################

    def getStateFromFlags(self,state, pkts):
        """ 
        Analyze the flags given and return a summary of the state. Should work with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        try:
            #self.outputqueue.put('06|database|[DB]: State received {}'.format(state))
            pre = state.split('_')[0]
            try:
                # Try suricata states
                """
                 There are different states in which a flow can be. 
                 Suricata distinguishes three flow-states for TCP and two for UDP. For TCP, 
                 these are: New, Established and Closed,for UDP only new and established.
                 For each of these states Suricata can employ different timeouts. 
                 """
                if 'new' in state or 'established' in state:
                    return 'Established'
                elif 'closed' in state:
                    return 'NotEstablished'

                # We have varius type of states depending on the type of flow.
                # For Zeek 
                if 'S0' in state or 'REJ' in state or 'RSTOS0' in state or 'RSTRH' in state or 'SH' in state or 'SHR' in state:
                    return 'NotEstablished'
                elif 'S1' in state or 'SF' in state or 'S2' in state or 'S3' in state or 'RSTO' in state or 'RSTP' in state or 'OTH' in state: 
                    return 'Established'

                # For Argus
                suf = state.split('_')[1]
                if 'S' in pre and 'A' in pre and 'S' in suf and 'A' in suf:
                    """
                    Examples:
                    SA_SA
                    SR_SA
                    FSRA_SA
                    SPA_SPA
                    SRA_SPA
                    FSA_FSA
                    FSA_FSPA
                    SAEC_SPA
                    SRPA_SPA
                    FSPA_SPA
                    FSRPA_SPA
                    FSPA_FSPA
                    FSRA_FSPA
                    SRAEC_SPA
                    FSPA_FSRPA
                    FSAEC_FSPA
                    FSRPA_FSPA
                    SRPAEC_SPA
                    FSPAEC_FSPA
                    SRPAEC_FSRPA
                    """
                    return 'Established'
                elif 'PA' in pre and 'PA' in suf:
                    # Tipical flow that was reported in the middle
                    """
                    Examples:
                    PA_PA
                    FPA_FPA
                    """
                    return 'Established'
                elif 'ECO' in pre:
                    return 'ICMP Echo'
                elif 'ECR' in pre:
                    return 'ICMP Reply'
                elif 'URH' in pre:
                    return 'ICMP Host Unreachable'
                elif 'URP' in pre:
                    return 'ICMP Port Unreachable'
                else:
                    """
                    Examples:
                    S_RA
                    S_R
                    A_R
                    S_SA 
                    SR_SA
                    FA_FA
                    SR_RA
                    SEC_RA
                    """
                    return 'NotEstablished'
            except IndexError:
                # suf does not exist, which means that this is some ICMP or no response was sent for UDP or TCP
                if 'ECO' in pre:
                    # ICMP
                    return 'Established'
                elif 'UNK' in pre:
                    # ICMP6 unknown upper layer
                    return 'Established'
                elif 'CON' in pre:
                    # UDP
                    return 'Established'
                elif 'INT' in pre:
                    # UDP trying to connect, NOT preciselly not established but also NOT 'Established'. So we considered not established because there
                    # is no confirmation of what happened.
                    return 'NotEstablished'
                elif 'EST' in pre:
                    # TCP
                    return 'Established'
                elif 'RST' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are reseted when finished and therefore are established
                    # It can happen that is reseted being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                elif 'FIN' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are finished with FIN when finished and therefore are established
                    # It can happen that is finished being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                else:
                    """
                    Examples:
                    S_
                    FA_
                    PA_
                    FSA_
                    SEC_
                    SRPA_
                    """
                    return 'NotEstablished'
            #self.outputqueue.put('01|database|[DB] Funcion getFinalStateFromFlags() We didnt catch the state. We should never be here')
            #return None modificado por un valor concreto!
            return None
            return 'Indefinido' 
        except Exception as inst:
            #self.outputqueue.put('01|database|[DB] Error in getFinalStateFromFlags() in database.py')
            #self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            #self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            #self.print(traceback.format_exc())
            return 'Indefinido' 

    def obtaincountersbyType(self,flows):
    #en lugar de un dataset ahora recibo un diccionario/lista de flujos
        d = {}
        d2 = {}

        for key in flows.keys():       
            f = flows[key]
            flow_dict = json.loads(f)    
            #t.SrcAddr --> flow_dict['saddr']
            #t.DstAddr --> flow_dict['daddr']     
            #t.State --> flow_dict['state']
            #t.TotPkts --> flow_dict['pkts']
            #t.Proto --> flow_dict['proto']
            #t.Label -->flow_dict['ensemble_label']
            srcAddr = flow_dict['saddr']
            dstAddr = flow_dict['daddr']     
            state = flow_dict['state']
            totPkts = flow_dict['pkts']
            proto = flow_dict['proto']
            totBytes = flow_dict['allbytes']
            ensemble_label = flow_dict['ensemble_label']
                   
                   
            if srcAddr not in d.keys():
                d[srcAddr] = {'total1': 0.0, 'normal': 0.0, 'malicious': 0.0 }
            if dstAddr not in d[srcAddr].keys():
                d[srcAddr][dstAddr] = {'total2': 0.0, 'normal': 0.0, 'malicious': 0.0}
                d2[str(srcAddr)+"-"+str(dstAddr)] = {'SrcAddr': srcAddr, 'DstAddr': dstAddr, 'TCPEstablishedPercentegeMW': 0.00, 'TCPNotEstablishedPercentegeMW': 0.00, 'UDPEstablishedPercentegeMW': 0.00, 'UDPNotEstablishedPercentegeMW': 0.00, 'cantTCPEMW': 0,'cantTCPNEMW': 0, 'cantUDPEMW': 0, 'cantUDPNEMW': 0, 'cantTCPE': 0,'cantTCPNE': 0, 'cantUDPE': 0, 'cantUDPNE': 0, 'totalFlows': 0, 'totalPackets': 0, 'totalBytes': 0, 'TCPELabel':'normal', 'TCPNELabel':'normal', 'UDPELabel':'normal', 'UDPNELabel':'normal', 'PredictLabel':'normal'}
            d2[str(srcAddr)+"-"+str(dstAddr)]['totalFlows']+= 1
            d2[str(srcAddr)+"-"+str(dstAddr)]['totalPackets']+= totPkts
            d2[str(srcAddr)+"-"+str(dstAddr)]['totalBytes']+= totBytes
            if proto not in d[srcAddr][dstAddr].keys():
                d[srcAddr][dstAddr][proto] = {'total3': 0.0, 'normal': 0.0, 'malicious': 0.0 }
            state=self.getStateFromFlags(state,totPkts)
            if state not in d[srcAddr][dstAddr][proto].keys():
                d[srcAddr][dstAddr][proto][state] = {'total4': 0.0, 'normal': 0.0, 'malicious': 0.0 }
            d[srcAddr]['total1'] += 1
            print('PASO 4')
            d[srcAddr][dstAddr]['total2'] += 1
            print('PASO 5')
            d[srcAddr][dstAddr][proto]['total3'] += 1
            print('PASO 6')
            d[srcAddr][dstAddr][proto][state]['total4'] += 1
            print('PASO 7')
       
            #For each pair IPSrc-IpDst I want to know the total of flows, the total of bytes, the total of packets
            #total2 is the total of flows counter, totalPackets is the total of packets, totalBytes is the total of bytes
            print(ensemble_label)
            if ensemble_label == 'normal':
                d[srcAddr]['normal'] += 1
                print('PASO 8')
                d[srcAddr][dstAddr]['normal'] += 1
                print('PASO 9')
                d[srcAddr][dstAddr][proto]['normal'] += 1
                print('PASO 10')
                d[srcAddr][dstAddr][proto][state]['normal'] += 1
                print('PASO 11')
            else:
                if(ensemble_label == 'malicious'):
                    d[srcAddr]['malicious'] += 1
                    print('PASO 12')
                    d[srcAddr][dstAddr]['malicious'] += 1
                    print('PASO 13')
                    d[srcAddr][dstAddr][proto]['malicious'] += 1
                    print('PASO 14')
                    d[srcAddr][dstAddr][proto][state]['malicious'] += 1
                    print('PASO 15')

        return d,d2

    def get_stats(self, d,src, dst, proto, state):
        pmalicious_src = d[src]['malicious']/d[src]['total1']
        pmalicious_src_dst = d[src][dst]['malicious']/d[src][dst]['total2']
        pmalicious_src_dst_proto = d[src][dst][proto]['malicious']/d[src][dst][proto]['total3']
        pmalicious_src_dst_proto_state = 100*(d[src][dst][proto][state]['malicious'])/(d[src][dst][proto][state]['total4'])
        return pmalicious_src_dst_proto_state

    def get_percentegesandcounters(self,flows,d,d2,thresholdCounterMaliciousFlows,thresholdPercentegeMaliciousFlows):
    #flows are all flows for each profile of a timewindows obtained from DB
    #d is the dictionary created with different counters
    #d2 is the dictionary created to calculate totals and percenteges
    #thresholdCounterMaliciousFlows and thresholdPercentegeMaliciousFlows are thresholds to determinate IPDestination label
    #based on amount of flows labeled as malicious and percentege of flows labeled as malicious

        for key in flows.keys():       
            f = flows[key]
            flow_dict = json.loads(f)    
        
            src = flow_dict['saddr']
            dst = flow_dict['daddr']     
            state = flow_dict['state']
            totPkts = flow_dict['pkts']
            proto = flow_dict['proto']
            totBytes = flow_dict['allbytes']
            ensemble_label = flow_dict['ensemble_label']
    
            state=self.getStateFromFlags(state,totPkts)
            pstate = self.get_stats(d,src, dst, proto, state)
            key=src+"-"+dst
                
            if(proto=='tcp'):
                if (state=='Established'):
                    d2[key]['TCPEstablishedPercentegeMW']=pstate
                    d2[key]['cantTCPEMW']=d[src][dst][proto][state]['malicious']
                    d2[key]['cantTCPE']=d[src][dst][proto][state]['total4']
                else:
                    if (state=='NotEstablished'):
                        d2[key]['TCPNotEstablishedPercentegeMW']=pstate
                        d2[key]['cantTCPNEMW']=d[src][dst][proto][state]['malicious']
                        d2[key]['cantTCPNE']=d[src][dst][proto][state]['total4']
            else:
                if(proto=='udp'):
                    if (state=='Established'):
                        d2[key]['UDPEstablishedPercentegeMW']=pstate
                        d2[key]['cantUDPEMW']=d[src][dst][proto][state]['malicious']
                        d2[key]['cantUDPE']=d[src][dst][proto][state]['total4']
                    else:
                        if (state=='NotEstablished'):
                            d2[key]['UDPNotEstablishedPercentegeMW']=pstate
                            d2[key]['cantUDPNEMW']=d[src][dst][proto][state]['malicious']
                            d2[key]['cantUDPNE']=d[src][dst][proto][state]['total4']
            if((d2[key]['TCPEstablishedPercentegeMW']>thresholdPercentegeMaliciousFlows)and(d2[key]['cantTCPEMW']>thresholdCounterMaliciousFlows)):
                d2[key]['TCPELabel']='malicious'
                d2[key]['PredictLabel']='malicious'
            if((d2[key]['TCPNotEstablishedPercentegeMW']>thresholdPercentegeMaliciousFlows)and(d2[key]['cantTCPNEMW']>thresholdCounterMaliciousFlows)):
                d2[key]['TCPNELabel']='malicious'
                d2[key]['PredictLabel']='malicious'
            if((d2[key]['UDPEstablishedPercentegeMW']>thresholdPercentegeMaliciousFlows)and(d2[key]['cantUDPEMW']>thresholdCounterMaliciousFlows)):
                d2[key]['UDPELabel']='malicious'
                d2[key]['PredictLabel']='malicious'
            if((d2[key]['UDPNotEstablishedPercentegeMW']>thresholdPercentegeMaliciousFlows)and(d2[key]['cantUDPNEMW']>thresholdCounterMaliciousFlows)):
                d2[key]['UDPNELabel']='malicious'
                d2[key]['PredictLabel']='malicious'
        return d2
   
##########################End Phase 2 functions########################################################                         

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    return True
                if message['channel'] == 'tw_closed':
                    # Ensemble process 
                    data = str(message['data'])
                    print(data)
                    twidposition=data.find("t")
                    profileid = data[0:twidposition-1]
                    twid = data[twidposition:len(data)]
                    
                    print('Ensemble module running')
                    #Obtain all flows from the profileid and twid when the timewindows closed
                    flows = __database__.get_all_flows_in_profileid_twid(profileid,twid)
                    
                    labels = ['malicious','normal']
                    print('Original flows')
                    print(flows)
                    ###clean_flows = []
                    ###uids = []
                    if flows is not None:
                        for key in flows.keys():
                            ###uids.append(key)       
                            #Random value to assign modules labels
                            #when classifiers work and the assign module labels delete next 6 lines
                            label1 = random.choice(labels)
                            label2 = random.choice(labels)
                            label3 = random.choice(labels)
                            __database__.add_module_label_to_flow(profileid,twid,key,'test1',label1) 
                            __database__.add_module_label_to_flow(profileid,twid,key,'test2',label2)
                            __database__.add_module_label_to_flow(profileid,twid,key,'test3',label3)
                            __database__.add_ensemble_label_to_flow(profileid,twid,key,'NONE')
                    print('Flows with random labels to simulate classifiers results to assign flow labels')
                    flows = __database__.get_all_flows_in_profileid_twid(profileid,twid)
                    print(flows)
                    if flows is not None:
                        for key in flows.keys():       
                            f = flows[key]
                            flow_dict = json.loads(f)    
                            modulesLabels = flow_dict['modules_labels']
                            ensembleLabel = self.phase1voting(modulesLabels)
                            print(profileid)
                            print(twid)
                            print(key)
                            print(ensembleLabel)
                            __database__.add_ensemble_label_to_flow(profileid,twid,key,ensembleLabel)
                    flows = __database__.get_all_flows_in_profileid_twid(profileid,twid)
                    print('flows with ensemble label')
                    print(flows)                    
                    ## Phase 2 ensembling##
                    if flows is not None:
                        countersdict,initialpercentegesdict=self.obtaincountersbyType(flows)
                        for key in countersdict.keys():
                            print(key)
                            print(countersdict[key])
                        for key in initialpercentegesdict.keys():
                            print(key)
                            print(initialpercentegesdict[key])
                        #to test I do it separatly, I must think more if it is necessary iterate twice
                        ##thresholdCounterMaliciousFlows and thresholdPercentageMaliciousFlows are values determined by the training
                        ##we must read these values from a configuration file or ???? (I don't know yet)
                        thresholdCounterMaliciousFlows=0
                        thresholdPercentegeMaliciousFlows=25
                        finalpercentegesdict=self.get_percentegesandcounters(flows,countersdict,initialpercentegesdict,thresholdCounterMaliciousFlows,thresholdPercentegeMaliciousFlows)                     
                        for key in finalpercentegesdict.keys():
                            print(key)
                            print(finalpercentegesdict[key])
                     ## End Phase 2 ensembling##
                     ## Phase 3 ensembling#####
                                      
                     
                     ## End Phase 3 ensembling##
                        
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
