rule Win_Trojan_Agent_35172
{
strings:
	$a0 = { 9c87f840565be80000000059f7de8bd1c1cb05545b81e973100100fd4b514f4781c2350000008bc23ae58bc36800000000 }

condition:
	$a0
}

        
