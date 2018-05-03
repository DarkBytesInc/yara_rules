rule Unix_Worm_Ramen_4
{
strings:
	$a0 = { 333e72616d656e2063726577 }
	$a1 = { 6861636b657273206c6f[0-16]7665206e6f6f646c65732e99 }

condition:
	$a0 and $a1
}

        
