rule Win_Trojan_Zlob_2205
{
strings:
	$a0 = { c685fcfeffff68c685fdfeffff70c685fefeffff6d[0-40]c685fffeffff49c68500ffffff6ec68501ffffff73c68502ffffff75[0-40]c68503ffffff72c68504ffffff61c68505ffffff6ec68506ffffff63c68507ffffff65c68508ffffff45c68509ffffff76c6850affffff65[0-50]c6850bffffff6ec6850cffffff74c6850dffffff45c6850effffff78 }

condition:
	$a0
}

        
