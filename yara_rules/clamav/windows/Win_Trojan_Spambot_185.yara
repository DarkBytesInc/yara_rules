rule Win_Trojan_Spambot_185
{
strings:
	$a0 = { daeb363539de8d2be3ca9558e467037518ad8a7bc04a8983b6ffff7ff0559734e10dd18bddd289dae9cc3d37557a9c7ec42d332b16a735ffffffff3ca399d9874cdae7b188214e19750630345c827b890d26457942b980a0796eeaffffffc75adbd5bfa29373a84927fdcef34736 }

condition:
	$a0
}

        
