rule Win_Trojan_Agent_34529
{
strings:
	$a0 = { b8????????b???99????2bc681f???099???89??c3 }

condition:
	$a0
}

        