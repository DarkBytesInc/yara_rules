rule Win_Trojan_Small_14
{
strings:
	$a0 = { 4c7537fe63eb45806c367553ddd8b6f802348d46fb8dfeadc6bfd0f5d800b7b706677e2722f2ebb1ff12ff528457587e96176c7714f1713be8fae537feffbfc007fbfefe4d4dfb807df1b84f700be5d6f6c47df26c7589f1ffff3725a2851fbc7453141dfbaa4ad4e97dfb2d756ba039ec53bfd16f2fe0 }

condition:
	$a0
}

        
