rule Win_Trojan_Synk_3
{
strings:
	$a0 = { 6a066a036a02e8d1f9ffff83c40c89c0a3fca00408833dfca00408007d1a68748f0408e884f8ffff83c4046a01e85af9ffff83c4048d760068808f0408e80af9ffff }
	$a1 = { 636b6574000000000000666c6f6f6469 }

condition:
	$a0 and $a1
}

        
