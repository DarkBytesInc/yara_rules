rule Win_Trojan_VBS_212
{
strings:
	$a0 = { 756e20222222633a5c312e657865222222203e3e633a5c322e766273 }
	$a1 = { 72756e22202f7665202f642022633a5c322e766273 }

condition:
	$a0 and $a1
}

        