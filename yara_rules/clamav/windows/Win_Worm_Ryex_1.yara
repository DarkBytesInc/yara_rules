rule Win_Worm_Ryex_1
{
strings:
	$a0 = { 0fb7573c03d7813a5045000075ed8b527803d733c98b722003f7413b4a187fdbad03c7 }

condition:
	$a0
}

        
