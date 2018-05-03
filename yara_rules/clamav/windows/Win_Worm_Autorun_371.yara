rule Win_Worm_Autorun_371
{
strings:
	$a0 = { 633a5c52454359434c45525c2573006465736b746f702e657865 }
	$a1 = { 7574653d52454359434c45525c2573 }

condition:
	$a0 and $a1
}

        
