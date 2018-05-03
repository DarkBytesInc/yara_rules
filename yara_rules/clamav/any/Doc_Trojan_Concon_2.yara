rule Doc_Trojan_Concon_2
{
strings:
	$a0 = { 436f6e73742045676f203d2022636f6e636f6e22 }
	$a1 = { 53746f6a2e5642436f6d706f6e656e74732e496d706f7274204578706f727466 }

condition:
	$a0 and $a1
}

        
