rule Win_Trojan_Sirius_6
{
strings:
	$a0 = { ba5198be2308f6062e31174a43434e85f675f5f8a054a7984ec5cc754499b720a566f7d00b270add8bb9785543ec04867158cf408586bb981011a353 }

condition:
	$a0
}

        
