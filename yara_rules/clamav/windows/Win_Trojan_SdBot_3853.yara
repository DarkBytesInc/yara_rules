rule Win_Trojan_SdBot_3853
{
strings:
	$a0 = { 46c87f1e910ade69df41631b53b1e09b477200528a67d50ebd58cc02d00e10a3fbc82da58b3cbcc9860c4c7e8a5621ed2d44b008be73a057f57c0f1d45da61b61e444b4baed7f746f1ecfeb8e153529dc0eefdcd24 }

condition:
	$a0
}

        
