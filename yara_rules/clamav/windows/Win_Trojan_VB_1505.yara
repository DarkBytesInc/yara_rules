rule Win_Trojan_VB_1505
{
strings:
	$a0 = { 5c72756e5c2220262022[0-16]5c222026202277696e646f7722202620222e65786522 }

condition:
	$a0
}

        
