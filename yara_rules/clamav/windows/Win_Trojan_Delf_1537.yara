rule Win_Trojan_Delf_1537
{
strings:
	$a0 = { 8b55fcb80c001513e88329ffff85c07e248d8570feffff5033c9ba0c0015138b45fce89db0ffff8b9570feffff8d45fce84b25ffff8b55fcb830001513e84e29ffff85c07e388d856cfeffff50e84e32ffff8d9568feffffe81bb1ffff8b8d68feffffba300015138b45fce854b0ffff8b956cfeffff8d45fce80225ffff }

condition:
	$a0
}

        
