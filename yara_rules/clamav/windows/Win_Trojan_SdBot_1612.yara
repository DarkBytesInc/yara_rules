rule Win_Trojan_SdBot_1612
{
strings:
	$a0 = { 8df3934b42727567ed7f6809fd7e1f7b4cc0ceb026545e4cf5f3c2eb55b5af618cb4d618bfc09a37895e0e1353b96aba5f865ec235983e324a4bb36fd24d5fa74dfa6cb36fc3df98432e048453432567 }

condition:
	$a0
}

        
