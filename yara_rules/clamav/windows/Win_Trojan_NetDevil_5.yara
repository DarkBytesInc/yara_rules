rule Win_Trojan_NetDevil_5
{
strings:
	$a0 = { 0e000000264e616d653d5b76696374696d3d0000ffffffff4b0000005d2b5b6e6574646576696c20312e31207372765d2b5b2b69703d }

condition:
	$a0
}

        
