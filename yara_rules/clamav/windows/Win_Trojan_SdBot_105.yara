rule Win_Trojan_SdBot_105
{
strings:
	$a0 = { 1c6d1aaff3c395216a0e24ecc8695d19ff4a60480e70d550e21245d2e3980843beb6c9486189749ca70a523a5e469e35c228434d50aa6a0253594e206679d64aedfa453a4fb44a0a46294e0ece2d739b06eb5bb8694b427b2f515d10b11e642d5b013a3f5d57cf1c684e3a6d3cffc145782aaca56ae211b70d0ea890049a0881b1434b8b310d0ab69213f830da05d95761d7736495 }

condition:
	$a0
}

        