rule Win_Trojan_Lowzones_55
{
strings:
	$a0 = { 2d0380c444c4c031bdac887a7ba8b7263458ebb709320631222a89f4a8fef7cea5a533454d035eb5a3fedd16c419c74b050d19c1e74effd80693344085b507478e0cc4177c2932eb627a1b2f3ed03330354bec96e0926ce45e400ad1b929881b177e51073f3d3b6a18268da7be575ccd57533c1cab1a5d8029002e878cbf4d14337bdb8c76e2325ad3b60a657b956da7 }

condition:
	$a0
}

        