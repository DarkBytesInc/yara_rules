rule Win_Trojan_Bancos_1088
{
strings:
	$a0 = { acea3b53409af1a0b59b154056b954f6c15d63c1dbb6b1e8fd7a5bdac2d18478d92c1758e9f099774d047b13fd62755895f531418716cb2b9feb183360acc00f1e0c9e63ffce8cfb15de92454062a5aaed7e8a9feb }

condition:
	$a0
}

        
