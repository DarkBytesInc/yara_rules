rule Win_Trojan_SGWW2202_1
{
strings:
	$a0 = { 83c424e8000000005d81ed0a1040008b85331640005083ec20b80f0000008985da144000bf }

condition:
	$a0
}

        
