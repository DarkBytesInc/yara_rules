rule Win_Trojan_Hupigon_253
{
strings:
	$a0 = { 36ec53cc248cd838aaf2c11c604d25862c394960c70e1c7446bd77d193edb12b0764a1772bc3a4f4302b8f8e6f786dfeab0ddcba0ad77d330f50cc6daa851f2c88b4e9f9680c4dd4cabc868b8a253c9352b9cdb56fc28e05f45921bdecd2c758a14649cc9e1affceedc58356bc54 }

condition:
	$a0
}

        
