rule Win_Worm_Nihilit_4
{
strings:
	$a0 = { 6563686f206e202577696e626f6f74646972255c616e67656c647573742e6261733e3e626173 }

condition:
	$a0
}

        
