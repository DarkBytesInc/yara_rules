rule Win_Trojan_Pestdoor_2
{
strings:
	$a0 = { 5dc30000ffffffff010000004e000000ffffffff1b000000504553542056332e32205241542053657276657220456469 }

condition:
	$a0
}

        
