rule Html_Trojan_VBSDisableAV_1
{
strings:
	$a0 = { 636d642e6578652f6374736b696c6c6176706363[0-33]2f6374736b696c6c617670706d2229 }

condition:
	$a0
}

        
