rule Win_Trojan_Win_46
{
strings:
	$a0 = { 5501000091e34e894d0c8bd18b5a3c66813c13504575358db413f8000000f646242074288b4e }

condition:
	$a0
}

        
