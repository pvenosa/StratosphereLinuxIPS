# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform
import json

# Your imports


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
        taking all the prcocesses into account

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
                    # 
                    #
                    #
                    print('Ensemble module running')
                    profiles = __database__.getProfiles()
                    print('profiles obtained')
                    flows=[]
                    for profileid in profiles:
                        (lasttwid, lastid_time) = __database__.getLastTWforProfile(profileid)[0]
                        flowsprofile = __database__.get_all_flows_in_profileid_twid(profileid,lasttwid)
                        flows.append(flowsprofile)
                        print('last tw id obtained and flows for the tw and profileid obtained')
                        print (lasttwid)
                        print(lastid_time)
                        #proceso ese conjunto de flujos? aplico fase 1, 2 y 3 a ese conjunto que está vinclulado 
                        # a una IP origen?
                        # o o guardo todos los flujos en una estructura y los proceso a todos como 
                        # se hizo en los experimentos
                        #obtener IP del profile
                    print (len(flows))
                    for flow in flows:
                        print(flow)
                        #for k in flow:
                        #    d = flow[k]
                        #    print(d)                         
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
