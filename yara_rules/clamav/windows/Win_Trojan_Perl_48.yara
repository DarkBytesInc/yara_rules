rule Win_Trojan_Perl_48
{
strings:
	$a0 = { 5c72756e202f76202277696e6c6f676f6e22[0-27]73797374656d33325c5c647269766572735c5c }
	$a1 = { 2e706c222e2722202f66 }

condition:
	$a0 and $a1
}

        
