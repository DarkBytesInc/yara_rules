rule Win_Spyware_Banker_2686
{
strings:
	$a0 = { 82d89e931c1568a553884f99c62fddf1b287bb20829a375f0d5739420f4106a9cd8ce65c2885e4cba69a9ac403bb3d1873b283931b14cbee8b8569b7850e6708c062a6a8e2cdee2f53c6afffb7af }

condition:
	$a0
}

        
