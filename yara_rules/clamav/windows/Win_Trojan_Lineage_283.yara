rule Win_Trojan_Lineage_283
{
strings:
	$a0 = { ee77d06c0deb09822daac95635ffb0703ea1e335947fe594f611e875ae6e15a5d60a2540a24752b29c9eb54ce2d2737ff03137ceed33883ab5e0829ef6ffa015cd05d83c8f2dee39c413f861cb86437c85a1edc9700c4a3a0f937261 }

condition:
	$a0
}

        
