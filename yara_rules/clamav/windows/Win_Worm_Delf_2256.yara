rule Win_Worm_Delf_2256
{
strings:
	$a0 = { 53657879204769726c732e736372 }
	$a1 = { 5c43757272656e7456657273696f6e5c52756e }
	$a2 = { 5c446973616c6c6f7752756e }

condition:
	$a0 and $a1 and $a2
}

        
