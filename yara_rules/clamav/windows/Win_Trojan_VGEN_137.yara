rule Win_Trojan_VGEN_137
{
strings:
	$a0 = { 2fcd21268b4716251f003d1e007503e9870026ff771626ff771831c08ed8c7069000ae018c0e9200b8023d8bd383c2 }

condition:
	$a0
}

        
