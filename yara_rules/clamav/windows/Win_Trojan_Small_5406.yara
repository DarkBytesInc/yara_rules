rule Win_Trojan_Small_5406
{
strings:
	$a0 = { 2e777269746528223c79693666787269 }
	$a1 = { 783e79222e7265706c616365282f5b69787936665d2f672c22 }

condition:
	$a0 and $a1
}

        
