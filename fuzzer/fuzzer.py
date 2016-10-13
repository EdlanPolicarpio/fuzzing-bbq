#!/usr/bin/python

import sys
from katnip.targets.tcp import TcpTarget
from kitty.fuzzers import ServerFuzzer
from kitty.controllers import EmptyController
from kitty.model import *
from kitty.interfaces.web import WebInterface

#from katnip.targets.tcp import TcpTarget
#from kitty.fuzzers import * 
#from kitty.controllers import * 
#from kitty.model import *
#from kitty.interfaces.web import * 


http_template = Template(name='HTTP_GET_V3', fields=[
	String('GET', name='method', fuzzable=False),   # 1. Method - a string with the value "GET"
	Delimiter(' ', name='space1', fuzzable=False),  # 1.a The space between Method and Path
	String('/index.html', name='path'),             # 2. Path - a string with the value "/index.html"
	Delimiter(' ', name='space2'),                  # 2.a. The space between Path and Protocol
	String('HTTP', name='protocol name'),           # 3.a Protocol Name - a string with the value "HTTP"
	Delimiter('/', name='fws1'),                    # 3.b The '/' after "HTTP"
	Dword(1, name='major version',                  # 3.c Major Version - a number with the value 1
	      encoder=ENC_INT_DEC),                 # encode the major version as decimal number
	Delimiter('.', name='dot1'),                    # 3.d The '.' between 1 and 1
	Dword(0, name='minor version',                  # 3.e Minor Version - a number with the value 1
	      encoder=ENC_INT_DEC),                      # encode the minor version as decimal number
	Static('\r\n\r\n', name='eom')                  # 4. The double "new lines" ("\r\n\r\n") at the end of the request
])
# Macros
SERVER_IP = "0.0.0.0"		# AKA localhost
SERVER_PORT = 2001
INTERFACE_PORT = 2002
RETRIES = 3

# Model
model = GraphModel("HTTP MODEL")
model.connect(http_template)

# Target
target = TcpTarget("tcpTest", SERVER_IP, SERVER_PORT, RETRIES, None, None)
controller = EmptyController("EmptyController")
target.set_controller(controller)

#Interface
interface = WebInterface(SERVER_IP, INTERFACE_PORT)

# Setting Fuzzer
fuzzer = ServerFuzzer("test", None, None)
fuzzer.set_target(target)
fuzzer.set_model(model)
fuzzer.set_interface(interface)
# fuzzer.set_delay_between_tests(0.02)

# Run Fuzzing
fuzzer.start()
print("Fuzzing Completed...")
print("NOTE: Kitty has its own WebInterface at SERVER_IP:INTERFACE_PORT")
raw_input("Press Enter to Exit...")
print("Exiting Fuzzer...")
fuzzer.stop()

