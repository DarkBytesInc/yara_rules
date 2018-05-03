rule Win_Worm_Gaobot_899
{
strings:
	$a0 = { 4b074dfe7c90ef4f44450f4b4a4f494e41676f6200daaae8fe4d2920fbc336cc2d3e2573044f66666c69fb2244dc9c1b056374d76f9aaeeb1a2e3b72035c3a736d625f61fb }

condition:
	$a0
}

        
