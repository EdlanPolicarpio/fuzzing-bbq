#!/usr/bin/python

from kitty.fuzzers.server import ServerFuzzer
from katnip.katnip.targets.tcp import TcpTarget
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
t = TcpTarget("tcpTest", '127.0.0.1', 5555, 10, None, None)
m = GraphModel("HTTP MODEL")
m.connect(http_template)
i = WebInterface('127.0.0.1', 5555)

s.set_target(t)
s.set_model(m)
s.set_interface(i)

s.start()
