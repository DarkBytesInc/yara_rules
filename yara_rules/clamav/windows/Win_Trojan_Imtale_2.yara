rule Win_Trojan_Imtale_2
{
strings:
	$a0 = { 342e312e300d0a0d0af0e0e7f0e0e1eef2e0edee20476f647a0d0a7777772e61736563686b612e72752f696d74616c650d0a49435123323932 }

condition:
	$a0
}

        
