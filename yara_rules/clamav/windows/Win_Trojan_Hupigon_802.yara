rule Win_Trojan_Hupigon_802
{
strings:
	$a0 = { 2b381dbb992526ce50e9e3d6bebdbf9f1bba641fb1d0c18575eda0b4ffdf257888bd5977b1d612b30f36bbd5823f20388dec5b67c23f2a029a01aafaa4034c6e0888f838e7b19b1c8c05eaef523c0a14e4052ce7a035b2153c6d68f767dca3 }

condition:
	$a0
}

        
