rule Win_Adware_Advertmen_1
{
strings:
	$a0 = { 5c506f6c69636965735c4578706c6f7265720025732e646c6c000054 }
	$a1 = { 6b2e2041647665727469736d656e2e636f6d2070726f7669 }

condition:
	$a0 and $a1
}

        
