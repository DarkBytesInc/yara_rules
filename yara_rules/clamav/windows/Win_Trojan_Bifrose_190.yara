rule Win_Trojan_Bifrose_190
{
strings:
	$a0 = { 1db38c0740c5740315b5040298e226c08a2ae02d9df93cba0980eac984e9d2f506f45300945a62f7361628df1fb95ed30063ef900fe99a0086a0b85fbd30ec3e0326420a }

condition:
	$a0
}

        
