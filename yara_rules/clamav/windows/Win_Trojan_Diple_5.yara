rule Win_Trojan_Diple_5
{
strings:
	$a0 = { 558bec81ecfc0100006aff6aff6affff15????4200546a03ff15????42003b042a743db8????40008d040255506a056a00ff15????420056e82300000087f4fc8d042483e8f88b00f0875424 }

condition:
	$a0
}

        
