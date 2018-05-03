rule Doc_Trojan_CoolDown_1
{
strings:
	$a0 = { 2e46696e642822436f6f6c22 }
	$a1 = { 5265706c616365576974683a3d22e7e0ebf3ef222c }

condition:
	$a0 and $a1
}

        
