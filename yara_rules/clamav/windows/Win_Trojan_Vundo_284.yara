rule Win_Trojan_Vundo_284
{
strings:
	$a0 = { 6800000000311c246823c10fb683c4048b9ca4fcffffff03d3c78424b1ffffff2016a09581ecfcffffff319c24fcffffffc18c24a7ffffffd9339c24fcffffffd34c24e0319c24fcffffff899ca4fcffffffe800000000 }

condition:
	$a0
}

        
