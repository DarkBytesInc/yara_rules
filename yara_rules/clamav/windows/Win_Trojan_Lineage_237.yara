rule Win_Trojan_Lineage_237
{
strings:
	$a0 = { 1ce37e451eab82b1e63a5ab3cd091ec5b835f50f1782be6bffdc3378b446a1610461072bda737a84dedd14e31268f21046b6263d8bfee54c090fd610c869255c1e65ed473b424d2d5aab4f6b9eecf779e0162d579e9fc35cb02a0da6 }

condition:
	$a0
}

        
