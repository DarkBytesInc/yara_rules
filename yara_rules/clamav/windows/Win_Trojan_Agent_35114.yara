rule Win_Trojan_Agent_35114
{
strings:
	$a0 = { de277d642a4eb352bd615175c83055d0ddfabdf1aa7a261aed364acf6211e9b11a92d4815836b48183b1f589e8178d32b3c770c3aa31f9e3c3117e84682563ec25 }

condition:
	$a0
}

        
