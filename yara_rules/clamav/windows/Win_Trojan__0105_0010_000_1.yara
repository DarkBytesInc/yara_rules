rule Win_Trojan__0105_0010_000_1
{
strings:
	$a0 = { 40a34e03c606410300b440ba0000b94203cd21b8004233c933d2cd21803e4103017405b91c00eb }

condition:
	$a0
}

        
