rule Win_Trojan_Moonlight_1
{
strings:
	$a0 = { b80001501e06e871003e8b860000a300013e8b860200a302018bf533ffb8500002122e8b861e00263b061e00742e0e }

condition:
	$a0
}

        
