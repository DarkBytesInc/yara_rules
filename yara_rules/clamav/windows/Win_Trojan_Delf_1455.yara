rule Win_Trojan_Delf_1455
{
strings:
	$a0 = { 45fc8b08ff51f05f5e5b595dc34245495f5a4855 }
	$a1 = { 329cebeb8a45ff5f5e5b8be55dc3000000ffffffff040000002e4e455700000000534556494e464f00558becb9060000006a006a004975 }

condition:
	$a0 and $a1
}

        
