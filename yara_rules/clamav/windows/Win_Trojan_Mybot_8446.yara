rule Win_Trojan_Mybot_8446
{
strings:
	$a0 = { 0dd5fe0d4730dfaa18165127fa885f13799c6cd78d10523f0e01031a0b8bd2050547fcbe9403c118dd05e035ded85df8c812d867f0cad20fdc75fcd94d066dbf18b7e81e3fe51dd09cc241227505bf5a47c2086804 }

condition:
	$a0
}

        
