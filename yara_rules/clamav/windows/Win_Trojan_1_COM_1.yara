rule Win_Trojan_1_COM_1
{
strings:
	$a0 = { fc368b2d44448d762c908b561490e80400eb182c34b9cd0031140bd27408f7040100740142424646e2eec394ca82f9 }

condition:
	$a0
}

        
