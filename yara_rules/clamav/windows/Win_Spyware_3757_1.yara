rule Win_Spyware_3757_1
{
strings:
	$a0 = { 6e63656e745c4965486f6f6b00558bec33c05568 }
	$a1 = { 616d653d000000ffffffff0600000026506173733d0000ffffffff020000006f6b0000ffffffff0500000044586f77 }

condition:
	$a0 and $a1
}

        
