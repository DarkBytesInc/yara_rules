rule Win_Trojan_Humble_1
{
strings:
	$a0 = { 65a6ef0c670d742353381121244400f6ca019a20706f603875352d3d205370f34451164104 }

condition:
	$a0
}

        
