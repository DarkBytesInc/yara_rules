rule Email_Trojan_Trojan_548
{
strings:
	$a0 = { 4265696a696e67204f6c796d7069637320706f7374706f6e656420696e646566696e6974656c79 }

condition:
	$a0
}

        
