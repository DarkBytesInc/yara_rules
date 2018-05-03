rule Html_Trojan_Fraudpack3875_1
{
strings:
	$a0 = { 5589e581c444ffffff53565731c08945e4ff45e4837de4057ef731d28955d4ff45d4837dd4057ef7c745c44f00000083 }

condition:
	$a0
}

        
