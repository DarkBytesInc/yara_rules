rule Win_Trojan_Virut_200
{
strings:
	$a0 = { e8??000000 }
	$a1 = { 558b6c2404816c2404??????00e8ebffffff8bc8e8e4ffffff2bc13d0001000073468b5c240881e300f0ffff81ed051040008a????????????????5a74088d9b00f0ffffebec }

condition:
	$a0 and $a1
}

        
