rule Win_Trojan_Milan_1
{
strings:
	$a0 = { cd21903c0390751990909090b05090bb740190b9400090ba000090cd269090909090b44c90 }

condition:
	$a0
}

        
