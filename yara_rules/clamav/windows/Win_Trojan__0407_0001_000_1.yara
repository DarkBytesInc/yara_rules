rule Win_Trojan__0407_0001_000_1
{
strings:
	$a0 = { 2d03008986b900b440b9b6008d960300cd21b000e81b00b440b903008d96b800cd215a5983c9 }

condition:
	$a0
}

        
