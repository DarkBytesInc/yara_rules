rule Win_Trojan_Small_4595
{
strings:
	$a0 = { 9031c391e8000000005883e809ba3301000001c289c352e8df0200008d833104000050ff933b010000cd038bbb23010000 }

condition:
	$a0
}

        