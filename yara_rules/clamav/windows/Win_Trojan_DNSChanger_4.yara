rule Win_Trojan_DNSChanger_4
{
strings:
	$a0 = { 8945f08d852cfbffff684410400050ff15181040008d852cfbffff683410400050ffd68d8594f2ffff508d852cfbffff50ffd68d45f850683f000f008d852cfbffff53506802000080ff1504104000 }

condition:
	$a0
}

        
