rule Win_Trojan_Lineage_292
{
strings:
	$a0 = { 801a3b451ebed6b57c9b9ece5c8d89319ec620d3b8e2083b73bf378ba080c2b6121e4cadd40ed1e9ab4c32c839c326d4eca69daa65baccae44f3051c37a44be936399791a13b66775f0f3442131b742f0d16c99b70cbea494ece0224 }

condition:
	$a0
}

        
