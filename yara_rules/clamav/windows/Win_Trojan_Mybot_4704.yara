rule Win_Trojan_Mybot_4704
{
strings:
	$a0 = { 6edd8e7f3c5cfa5031f940b87490f8fdd6df606fcd1e4fe2b16a4e35b8b76a0b873f3a2ed3bc7f46a5e79a7d48c3d648aa30bc468e6b81bcdee31a83f8a7f8afc41f9a8bdbb06c94e2e9e4290237d97b899d4d9fbbb37314dfb15db81f987a21bfaeb55abc07968a4432699100849182bc360af5017eeab7babbb1cdbdf8eec281edd35b9c70e72ddd18949cac52581a74df0a8847e7 }

condition:
	$a0
}

        