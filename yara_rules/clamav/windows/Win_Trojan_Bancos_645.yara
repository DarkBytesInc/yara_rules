rule Win_Trojan_Bancos_645
{
strings:
	$a0 = { 3cb33904f60b8402b867123af0d3823c19416be2623148b5a9d1bc2f6a7e08f28cabb3bc43d77521fb74a0bf44fa73b1b6adbdd63294fe88db511a7371111cbcd893c621764dc7ed9f2768ded12123c5a9f0 }

condition:
	$a0
}

        
