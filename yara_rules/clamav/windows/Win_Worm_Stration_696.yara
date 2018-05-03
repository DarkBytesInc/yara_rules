rule Win_Worm_Stration_696
{
strings:
	$a0 = { 8a4d6f304c05684083f8087cf3bec08740008d7d5ca5a5a533c0 }

condition:
	$a0
}

        
