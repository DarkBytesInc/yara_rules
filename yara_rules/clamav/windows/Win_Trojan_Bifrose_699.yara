rule Win_Trojan_Bifrose_699
{
strings:
	$a0 = { c16919b100dd58a4e831f4084900eaf31222f102746207e4fcc5e861d006fd2aec0538e1bf85feee805e9ab319000df20b1181b8c7ce00fc836b229e686a430738a26cc8 }

condition:
	$a0
}

        
