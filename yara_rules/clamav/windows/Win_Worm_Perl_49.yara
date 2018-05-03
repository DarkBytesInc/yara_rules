rule Win_Worm_Perl_49
{
strings:
	$a0 = { 247365727665722f65706964656d75732e706c }
	$a1 = { 6f70656e28746d702c223e222c2274336d702e746d70 }
	$a2 = { 6e2865706d69[0-6]6d69727a2e747874 }

condition:
	$a0 and $a1 and $a2
}

        
