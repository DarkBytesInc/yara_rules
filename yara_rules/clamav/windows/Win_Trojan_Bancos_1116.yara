rule Win_Trojan_Bancos_1116
{
strings:
	$a0 = { 640787ad323e983cbafde2359a58081de9e082c229d993f327ecb34c368df7aa468ecc344b4c77017ff84b73a2d12757ae1cc21fb365277fee8bdbc810dfe51bc23fe8fad84be247460ebd3076e5fb9fe817c80b2e04ca30eb80b56faba593a31d200d2297f5 }

condition:
	$a0
}

        
