rule Win_Trojan_W_266
{
strings:
	$a0 = { e8000000005d81ed071040008dbd24104000b92d06000081370000000083c704e2f5 }

condition:
	$a0
}

        
