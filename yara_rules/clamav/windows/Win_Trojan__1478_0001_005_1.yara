rule Win_Trojan__1478_0001_005_1
{
strings:
	$a0 = { 74053ce2f97501f8075f5958c39c2eff1e4001c3b80303cf5152c606370101c64503cc8b450ea3 }

condition:
	$a0
}

        
