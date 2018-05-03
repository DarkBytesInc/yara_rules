rule Email_Trojan_Trojan_551
{
strings:
	$a0 = { 66696c656e616d653d22416e67656c696e615f4a6f6c69652e726172 }

condition:
	$a0
}

        
