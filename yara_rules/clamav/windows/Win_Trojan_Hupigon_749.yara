rule Win_Trojan_Hupigon_749
{
strings:
	$a0 = { 972019a3257bfd442a4c723e4fa6f1bb868c7b4dfaf22367bbbf6d059810ce0d6bd2b1266d217c2457e231f2273d0d000c8f26cd630ec17c4a31eef952ec90b82cca362536932a6726dc04e77bb1 }

condition:
	$a0
}

        
