rule Win_Trojan_Diple_4
{
strings:
	$a0 = { 558bec81ecfc0100006aff6aff6a006a006affff15????42006a016a03ff15????42003b042a743cb8??2940008d040255506a056a00ff15????420050e82200000087f4fc8d042483e8f88b00f0874c }

condition:
	$a0
}

        
