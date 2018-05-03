rule Win_Worm_Python_4
{
strings:
	$a0 = { 5c5c43757272656e7456657273696f6e5c5c52756e[0-70]5c5c5c5c5f616c657374652e6578655c }

condition:
	$a0
}

        
