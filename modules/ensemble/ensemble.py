# Ensemble module implementation

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
from modules.virustotal.virustotal import VirusTotalModule
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
    
        self.vt = VirusTotalModule(outputqueue,config) 
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

###########################Phase 1 functions##########################################################
    
    def phase1voting(self,modulesLabels):
        weights = {'test1':1,'test2':3,'test3':1}
        maliciousVotes = 0
        normalVotes = 0
        ensembleLabel = ''
        for classifier, label in modulesLabels.items(): 
            if (label == 'malicious'):
                maliciousVotes = int(maliciousVotes+weights[classifier])
            else:
                normalVotes = int(normalVotes+weights[classifier])
        if (maliciousVotes > normalVotes):
            ensembleLabel = 'malicious'
        else:
            ensembleLabel = 'normal'
        return ensembleLabel

###########################End Phase 1 functions######################################################        
         
###########################Phase 2 functions##########################################################
###########################Phase 3 functions###########################################################
## In this phase we must decide the label for each pair IP Src address - IP Dst Address
## The label indicates if the entire set of flows for this pair source-destination is malicious or normal

    def obtaincountersbyType(self,flows):
    #For each pair IPSrc-IpDst we calculate the total of flows, the total of bytes, the total of packets
        d = {}
        d2 = {}

        for key in flows.keys():       
            flow_dict = flows[key]
            srcAddr = flow_dict['saddr']
            dstAddr = flow_dict['daddr']     
            state = flow_dict['state']
            totPkts = flow_dict['pkts']
            proto = flow_dict['proto']
            totBytes = flow_dict['allbytes']
            ensemble_label = flow_dict['modules_labels']['ensemble']
            
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
            if state not in d[srcAddr][dstAddr][proto].keys():
                d[srcAddr][dstAddr][proto][state] = {'total4': 0.0, 'normal': 0.0, 'malicious': 0.0 }
            d[srcAddr]['total1'] += 1
            d[srcAddr][dstAddr]['total2'] += 1
            d[srcAddr][dstAddr][proto]['total3'] += 1
            d[srcAddr][dstAddr][proto][state]['total4'] += 1
            
            print(ensemble_label)
            if ensemble_label == 'normal':
                d[srcAddr]['normal'] += 1
                d[srcAddr][dstAddr]['normal'] += 1
                d[srcAddr][dstAddr][proto]['normal'] += 1
                d[srcAddr][dstAddr][proto][state]['normal'] += 1
            else:
                if(ensemble_label == 'malicious'):
                    d[srcAddr]['malicious'] += 1
                    d[srcAddr][dstAddr]['malicious'] += 1
                    d[srcAddr][dstAddr][proto]['malicious'] += 1
                    d[srcAddr][dstAddr][proto][state]['malicious'] += 1
            
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
            flow_dict = flows[key]
            #flow_dict = json.loads(f)    
        
            src = flow_dict['saddr']
            dst = flow_dict['daddr']     
            state = flow_dict['state']
            totPkts = flow_dict['pkts']
            proto = flow_dict['proto']
            totBytes = flow_dict['allbytes']
            print('get_percentegesandcounters')
            ensemble_label = flow_dict['modules_labels']['ensemble']
    
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

###########################Phase 3 functions###########################################################
## In this phase we must decide the label for each IP Src address taking in account different TI feeds (VirusTotal Module,
##TIModule and Peer Module)
## The malicious label for IP Src Address indicates the host is infected
## The normal label for IP Src Address indicates the host is not infected
## Phase 3 label is written for each profileid in the Database 

    def buildPhase3DictionarywithVTInformation(self,finalpercentegesdict):
    ##The function receive the result phase 2 dictionary 
    ##Obtain VT Information for each IP address destination of each dictionary element (dictionary key)
    ##Return a dictionary where we have VT Information summarized for each IP Src Addr
                   
        phase3dictionarywithVTInformation= {}
         
         
        for key in finalpercentegesdict.keys():
            dstaddr = finalpercentegesdict[key]['DstAddr']
            srcaddr = finalpercentegesdict[key]['SrcAddr']
            predictlabel = finalpercentegesdict[key]['PredictLabel']
            totalFlows = finalpercentegesdict[key]['totalFlows']
            cantTCPEMW = finalpercentegesdict[key]['cantTCPEMW']
            cantTCPNEMW = finalpercentegesdict[key]['cantTCPEMW']
            cantUDPEMW = finalpercentegesdict[key]['cantUDPEMW']
            cantUDPNEMW = finalpercentegesdict[key]['cantUDPNEMW']
                            
            ####Get VirusTotal information for each destination
            url,download,referrer,communicating = self.vt.get_ip_vt_scores(dstaddr)
            print('VIRUS TOTAL MODULE OK!!!!!!!!!!!!!!!!!!!!!!!')
            print(url)
            print(download)
            print(referrer)
            print(communicating)
                        
            if srcaddr not in phase3dictionarywithVTInformation.keys():
                phase3dictionarywithVTInformation[srcaddr] = {'Phase2Label': predictlabel, 'Phase2Confidence': 0, 'VTSumUrl': 0.00, 'VTSumDownload': 0.00, 'VTSumReferrer': 0.00, 'VTSumCommunic': 0.00, 'totalFlows':0, 'totalMalwareFlows':0, 'TotalGroups':0,  'MaliciousGroups':0, 'VTConfidence':0, 'Phase3Confidence':0, 'Phase3Label':'NoSeteada'}           
            phase3dictionarywithVTInformation[srcaddr]['totalFlows']+=totalFlows
            phase3dictionarywithVTInformation[srcaddr]['totalMalwareFlows']+=int(cantTCPEMW+cantTCPNEMW+cantUDPEMW+cantUDPNEMW)
            ##The process calculate for each IP Source Address the sum of url ratio value, download ratio value
            ##referrer ratio value and communicating ratio value for all Ip destinations that IP Source communicates with
                            
            phase3dictionarywithVTInformation[srcaddr]['VTSumUrl']+=url
            phase3dictionarywithVTInformation[srcaddr]['VTSumDownload']+=download
            phase3dictionarywithVTInformation[srcaddr]['VTSumReferrer']+=referrer
            phase3dictionarywithVTInformation[srcaddr]['VTSumCommunic']+=communicating
            phase3dictionarywithVTInformation[srcaddr]['TotalGroups']+=1
            if (predictlabel == 'malware'):
                phase3dictionarywithVTInformation[srcaddr]['MaliciousGroups']+=1    
        
        return phase3dictionarywithVTInformation                
        
    def buildPhase3DictionarywithVTLabel(self,phase3dictionary,profileid,w1,w2,w3,w4,threshold1,threshold2,threshold3,p3weight):
                     
    ##CHECK THE FUNCTION LOGIC                        
        for key in phase3dictionary.keys():
            phase3dictionary[key]['VTConfidence']=(w1*phase3dictionary[key]['VTSumUrl'])+(w2*phase3dictionary[key]['VTSumDownload'])+(w3*phase3dictionary[key]['VTSumCommunic'])+(w4*phase3dictionary[key]['VTSumReferrer'])
            print(key)
            print(phase3dictionary[key])
                    
        for key in phase3dictionary.keys():
            w5=0
     
            if((phase3dictionary[key]['MaliciousGroups'])>=threshold3):
                w5=0.59
            else:
                if((phase3dictionary[key]['MaliciousGroups'])>=threshold2):
                    w5=0.55
                else:
                    if((phase3dictionary[key]['MaliciousGroups'])>=threshold1):
                        w5=0.5
            phase3dictionary[key]['Phase2Confidence']=w5
            phase3dictionary[key]['Phase3Confidence']=phase3dictionary[key]['Phase2Confidence']+phase3dictionary[key]['VTConfidence']
            if ((round(phase3dictionary[key]['Phase3Confidence'],2))>=(round(p3weight,2))):
                phase3dictionary[key]['Phase3Label']='malicious'
                print('WRITE DESCRIPTION######################!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                ##__database__.set_profile_as_malicious('147.32.81.174','Phase3Ensemble')
                __database__.set_profile_as_malicious(profileid,'EnsembleModuleLabel(using VT as TI):Malicious')
            else:
                phase3dictionary[key]['Phase3Label']='normal'
            print (phase3dictionary[key]['Phase3Label'])
        return phase3dictionary
            
###########################End Phase 3 functions#######################################################

    def run(self):
        try:
            # Main loop function
            processedKeys=set()
            
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
                    if flows is not None:
                        for key in flows.keys():
                            f = flows[key]
                            flow_dict = json.loads(f)
                            #Random value to assign modules labels
                            #when classifiers work and the assign module labels delete next 6 lines
                            label1 = random.choice(labels)
                            label2 = random.choice(labels)
                            label3 = random.choice(labels)
                            flow_dict['modules_labels']['test1'] = label1
                            flow_dict['modules_labels']['test2'] = label2
                            flow_dict['modules_labels']['test3'] = label3
                            #######
                            flows[key]=flow_dict                            
                    print('Flows with RANDOM LABELS to simulate classifiers results to assign flow labels')
                    #flows = __database__.get_all_flows_in_profileid_twid(profileid,twid)
                    print(flows)
                    if flows is not None:
                        print('entra al for del ensembling')
                        for key in flows.keys():
                            print(profileid)
                            print(twid)
                            print(key)
                            flow_dict = flows[key]
                            modulesLabels = flow_dict['modules_labels']
                            ensembleLabel = self.phase1voting(modulesLabels)
                            print(flow_dict)
                            flow_dict['modules_labels']['ensemble'] = ensembleLabel
                            flows[key]=flow_dict
                    print('flows with ensemble label')
                    print(flows)  
                    
                    if flows is not None:
                        print('Store Phase 1 and Phase 2labels in DB')
                        for key in flows.keys():   
                            labels =  __database__.get_modules_labels_from_flow(profileid, twid, key)
                            if labels:
                                flow_dict = flows[key]
                                label1 = flow_dict['modules_labels']['test1']
                                label2 = flow_dict['modules_labels']['test2']
                                label3 = flow_dict['modules_labels']['test3']
                                ensembleLabel = flow_dict['modules_labels']['ensemble']
                                ##Three next lines are only for test                      
                                __database__.add_module_label_to_flow(profileid,twid,key,'test1',label1) 
                                __database__.add_module_label_to_flow(profileid,twid,key,'test2',label2)
                                __database__.add_module_label_to_flow(profileid,twid,key,'test3',label3)
                                ###
                                __database__.add_module_label_to_flow(profileid,twid,key,'ensemble',ensembleLabel)
                            else:
                                print('Flow exists in the DB!!!')         
                    
                    phase2finalpercentegesdict = {}
                    ## Phase 2 ensembling##
                    if flows is not None:
                        print('PHASE 2 START')
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
                        phase2finalpercentegesdict=self.get_percentegesandcounters(flows,countersdict,initialpercentegesdict,thresholdCounterMaliciousFlows,thresholdPercentegeMaliciousFlows)                     
                        ##Following 3 lines are only for test Phase2 results                        
                        for key in phase2finalpercentegesdict.keys():
                            print(key)
                            print(phase2finalpercentegesdict[key])
                                                           
                    ## End Phase 2 ensembling##
                    
                    ## Phase 3 ensembling#####
                        print('PHASE 3 START')
                        ##Phase 3 Dictionary initialization
                        ####Build Phase3 Dictionary for each IP Source, based on Phase 2 Dictionary and VT Information 
                    
                        phase3dictionarywithVTInformation=self.buildPhase3DictionarywithVTInformation(phase2finalpercentegesdict)
                    
                        ###w1,w2,w3, w4 are weights for url ratio, download ratio, referrer ratio and communicating ratio 
                        w1=0.19
                        w2=0.8
                        w3=0.01
                        w4=0
                        ###threshold1, threshold2 and threshold3 must be parameters
                        threshold1 = 1
                        threshold2 = 5
                        threshold3 = 20
                        p3weight = 0.55
                    
                        phase3dictionarywithVTLabel=self.buildPhase3DictionarywithVTLabel(phase3dictionarywithVTInformation,profileid,w1,w2,w3,w4,threshold1,threshold2,threshold3,p3weight)
                     
                        ## End Phase 3 ensembling##
                    
                        for key in phase3dictionarywithVTLabel.keys():
                            print(phase3dictionarywithVTLabel[key])
                                          
                            if(phase3dictionarywithVTLabel[key]['Phase3Label'] == 'malicious'):
                                ##descripcion = __database__.get_loaded_malicious_ip(key)
                                descripcion = __database__.is_profile_malicious(profileid)
                                print('Get malicious profile descripcion')
                                print(descripcion)
                                
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
