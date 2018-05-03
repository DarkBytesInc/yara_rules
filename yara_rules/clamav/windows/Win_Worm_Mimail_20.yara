rule Win_Worm_Mimail_20
{
strings:
	$a0 = { 733e5c0418f8895a697020632a00ad588026c8a02460254a2555819255e50ddc }

condition:
	$a0
}

        
