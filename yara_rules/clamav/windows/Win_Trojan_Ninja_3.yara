rule Win_Trojan_Ninja_3
{
strings:
	$a0 = { 030100db50061ee800005e2e807cf8007403e87902b89190cd213d90197451e8a5033d72197449e84c048cc0488ec0 }

condition:
	$a0
}

        
