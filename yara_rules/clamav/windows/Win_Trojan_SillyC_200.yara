rule Win_Trojan_SillyC_200
{
strings:
	$a0 = { 989942e9c2b35794a6141019a6d45761489701b4b571f1ab96107501b9862846c44366f62b7b0a18 }

condition:
	$a0
}

        
