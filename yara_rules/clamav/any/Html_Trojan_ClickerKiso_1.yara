rule Html_Trojan_ClickerKiso_1
{
strings:
	$a0 = { 7368322e69733638362e636f6d2f6c696e6b2f73632f325f31345f372e7068703f753d68616f35393126747970653d3226773d3726683d31342666633d303036364646266267633d6666666666662662 }

condition:
	$a0
}

        