rule Win_Tool_Dos_4
{
strings:
	$a0 = { ae029a00003e025589e531c09a7c02ae02b007509a57023e02b000509a71023e02c606440200e85fffe877fbe8 }

condition:
	$a0
}

        
