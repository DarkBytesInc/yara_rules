rule Win_Trojan__0157_0006_001_1
{
strings:
	$a0 = { c983c200b9040089ff2d0000ba3001cd21b801578b0e41018b163f0189ff80c4008b1e3601 }

condition:
	$a0
}

        
