rule Win_Trojan_Delwin_44
{
strings:
	$a0 = { 696e206664697220662e64656c65746566696c652066696e6766696c652e70617468 }

condition:
	$a0
}

        
