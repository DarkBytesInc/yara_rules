rule Win_Trojan_Mybot_8482
{
strings:
	$a0 = { f1d00a030c18f0870afe5dbb7314375abce2d95a0ed78b62845fd6eded2dd034a0da988dacad85417819226fc0179d7b8e06670490f1fbebb5e0ab90d075f614c687e6487b14b1730c291c624f5d84cc889ec0aa21 }

condition:
	$a0
}

        
