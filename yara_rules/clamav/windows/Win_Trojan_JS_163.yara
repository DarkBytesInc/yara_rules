rule Win_Trojan_JS_163
{
strings:
	$a0 = { 3c69272b276672616d65 }
	$a1 = { 647728273c73272b2763726970743e73746172746469616c65722829 }

condition:
	$a0 and $a1
}

        
