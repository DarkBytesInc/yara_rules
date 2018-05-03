rule Win_Worm_Iksmas_4
{
strings:
	$a0 = { be0e27400081c35a4b000081eaf43d00008d7d088d4d3f42baaa1040008d70988917b89f }

condition:
	$a0
}

        
