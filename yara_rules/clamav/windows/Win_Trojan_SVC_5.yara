rule Win_Trojan_SVC_5
{
strings:
	$a0 = { 909090e800005e81ee03012e89844c0d065633d2b41480c470cd215e5681fa941975262e3abc750d771c721d56 }

condition:
	$a0
}

        
