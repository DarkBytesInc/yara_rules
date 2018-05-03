rule Html_Trojan_IRCWebloit_1
{
strings:
	$a0 = { 4c915e226e447a88899612aa24bc48d091e222ec44f8025615ac03558b44240ca0ec85c000752b6810231822ff98d93b11173ce87edd36586a0ba1f0fbb32a3c }

condition:
	$a0
}

        
