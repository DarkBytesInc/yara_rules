rule Win_Trojan_SdBot_1708
{
strings:
	$a0 = { 333231e464580abd0f00003371fed9061f6f776e6572d98033f1f361646d6564757e0921fea9ff204578706c6f69 }

condition:
	$a0
}

        
