rule Win_Trojan_SdBot_3811
{
strings:
	$a0 = { cd8a85e8c0ecc20b47fa68e1e556e90306d35ab21b1f1e44bdbd2d43ea50c9c9ba8a17453fee60d9ddddde154f92e9e9eded6a1bbeb5b9b9d29ed36db237339205cdd1426a0318daca490a9239f11d1356edf1f1f57223c6bdbdc1c11f669f76ba43 }

condition:
	$a0
}

        
