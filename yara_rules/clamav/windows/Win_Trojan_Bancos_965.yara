rule Win_Trojan_Bancos_965
{
strings:
	$a0 = { 585b981aa4b65287ec68e7dbbd54e2067ee70ac18cc795e5596d077a1cedeece9aed039669c2cd5cb12a6495d5cdb65e346e02eaf691b2ca26c36b50ce212ec29f6fea6f5827191d88e60d62da1cecd14ebfcde8cd692dd9 }

condition:
	$a0
}

        
