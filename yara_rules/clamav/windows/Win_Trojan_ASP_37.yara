rule Win_Trojan_ASP_37
{
strings:
	$a0 = { 2e6372656174656f626a65637428616126222e2226626229 }
	$a1 = { 6d6964287861312c692c31293d225c22 }

condition:
	$a0 and $a1
}

        
