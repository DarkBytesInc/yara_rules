rule Win_Spyware_162_2
{
strings:
	$a0 = { 7dc92559c015f47a4f0c23c1795f6a835bfff119af288e312bbdc9fde069d2db98e2ff9cad4d6ec4d017494ab00c796f7a8fdd8dc6644d1104b9f0d132a5391ffc3ea399914a55dfcc2a89368e1d3c2e7dca19f87f9dbf63c4db53420b46 }

condition:
	$a0
}

        
