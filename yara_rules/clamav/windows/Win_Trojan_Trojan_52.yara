rule Win_Trojan_Trojan_52
{
strings:
	$a0 = { 4da2082cdc5bad00cc67a796838f0bee1e630d2973f630a7077461ffce2e80afdcc8ad01f94778d639423f48bb4326dd50bcdf3bda7d452e4b01df97e59dc2306aedb881f7d03ae580ba6c1303c3d23e4298e3f6a1387fda22c3b7713ce0cd130cd30b5f86624f6eddbb40074ac131ec }

condition:
	$a0
}

        
