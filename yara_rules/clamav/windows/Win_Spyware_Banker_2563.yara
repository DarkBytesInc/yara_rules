rule Win_Spyware_Banker_2563
{
strings:
	$a0 = { acd9179a864af81d98992e08240aa0c76be3d79faba7da2cb1f8ac68cfc97d06d0995a6f636b66b2ea7e19eae23650fb2ca48a0744778c43c04817510745d00a7c10d0c3a8e0528688dcf9630d0c34c3 }

condition:
	$a0
}

        
