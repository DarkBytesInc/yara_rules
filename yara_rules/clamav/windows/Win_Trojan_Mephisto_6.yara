rule Win_Trojan_Mephisto_6
{
strings:
	$a0 = { fc368b2d81ed030144441e060e1fe82104e8e702e938012a2e657865002a2e002e2e005c000100000000f0ff000000 }

condition:
	$a0
}

        
