rule Win_Trojan_JS_185
{
strings:
	$a0 = { 3c7363726970743e666f722869696e646f63756d656e742e616c6c2e74616773293b }

condition:
	$a0
}

        
