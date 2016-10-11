#!/usr/bin/python

import sys
from kitty.fuzzers.server import ServerFuzzer
from katnip.targets.tcp import TcpTarget
from kitty.model import *
from kitty.interfaces.web import WebInterface


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
	Dword(1, name='minor version',                  # 3.e Minor Version - a number with the value 1
	      encoder=ENC_INT_DEC),                      # encode the minor version as decimal number
	Static('\r\n\r\n', name='eom')                  # 4. The double "new lines" ("\r\n\r\n") at the end of the request
])

s = ServerFuzzer("test", None, None)
t = TcpTarget("tcpTest", '127.0.0.1', 80, 10, None, None)
m = GraphModel("HTTP MODEL")
m.connect(http_template)
i = WebInterface('127.0.0.1', 80)

s.set_target(t)
s.set_model(m)
s.set_interface(i)

s.start()

s.stop
sys.exit(0)

def post_test(self):
    '''Called when test is done'''
    self._stop_process()
    ## Make sure process started by us
    assert(self._process)
    ## add process information to the report
    self.report.add('stdout', self._process.stdout.read())
    self.report.add('stderr', self._process.stderr.read())
    self.logger.debug('return code: %d', self._process.returncode)
    self.report.add('return_code', self._process.returncode)
    ## if the process crashed, we will have a different return code
    self.report.add('failed', self._process.returncode != 0)
    self._process = None
    ## call the super
    super(ClientProcessController, self).post_test()

def teardown(self):
        '''Called at the end of the fuzzing session, 
		override with victim teardown'''
        self._stop_process()
        self._process = None
        super(ClientProcessController, self).teardown()

def _stop_process(self):
    if self._is_victim_alive():
        self._process.terminate()
        time.sleep(0.5)
        if self._is_victim_alive():
            self._process.kill()
            time.sleep(0.5)
            if self._is_victim_alive():
                raise Exception('Failed to kill client process')

def _is_victim_alive(self):
    return self._process and (self._process.poll() is None)
