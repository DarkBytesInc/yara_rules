rule Win_Trojan_Packed_159
{
strings:
	$a0 = { c039083a603a843abc3ae83ac03ba83ca43dd83da83e903f004008004c00000088301031b03160328832003390333034 }

condition:
	$a0
}

        
