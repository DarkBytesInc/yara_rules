rule Win_Trojan_Hupigon_482
{
strings:
	$a0 = { a3ed720e05596bcfb4039ea7c5b11695244ad23c06a29e5e6695fe93c5804e11a36627060657c4b9bd27a8c68bbb7a120d73ecea3eedc9e4dee63082a58e884eac4c3a9aff00c957563205b808bc421c5945beb5bf78a6c8911a973f2dfeacc21a85eb1f }

condition:
	$a0
}

        
