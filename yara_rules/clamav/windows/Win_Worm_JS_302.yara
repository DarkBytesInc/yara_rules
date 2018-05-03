rule Win_Worm_JS_302
{
strings:
	$a0 = { 766172657865733d225c5c616e6a77736f696e686a2e65786522 }

condition:
	$a0
}

        
