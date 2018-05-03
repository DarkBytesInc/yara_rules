rule Html_Trojan_IRCFlooder_1
{
strings:
	$a0 = { 616c6c20636c6f6e65732077657265206b696c6c6564[20-100]6e69636b73657276 }

condition:
	$a0
}

        
