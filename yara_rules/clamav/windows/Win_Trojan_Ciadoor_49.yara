rule Win_Trojan_Ciadoor_49
{
strings:
	$a0 = { 23b519733ada6a2dd4f2beb223ef0296ffb3f1f2afe0b3ff4930423bb5d698afd0578828c39088b0e7e3e0bc689dfea8230c1e73ce45bc4c28500187f5573a90d269a5fda950194f0f7ce560dad9c8576cc07366e073061537 }

condition:
	$a0
}

        
