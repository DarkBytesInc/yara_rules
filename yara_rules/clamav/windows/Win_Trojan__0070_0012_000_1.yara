rule Win_Trojan__0070_0012_000_1
{
strings:
	$a0 = { 0e090190ba000190b44090b90d0090cd2190b80157908b0e0901908b16070190cd2190b43e }

condition:
	$a0
}

        
