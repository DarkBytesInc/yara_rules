rule Win_Trojan_Mybot_8509
{
strings:
	$a0 = { dc0dd85fa4fae2da71189729ccba635da086db5b73bdf4e621208c2f98ed4d7202c6a804ce514f1b8b7554615de93493f9e5b6e9fdd5437d9fad15acfabe2286e02d3615070c196482ec63235bd9af6f04f26048a0 }

condition:
	$a0
}

        
