rule Win_Trojan_Ciadoor_241
{
strings:
	$a0 = { cda09ff0f43686e5cbdbe03bc7caebb2dc0a9b4b028e8a5ec52d541f2943593a8f85e7e7f7eba32476e8ffbf107c8274caba3c2f7ffd49244c1afede7aff90e4ce07b942079e2a71b8196ebb38d1638fb353c6647d1b4adc9f44f4cfe3d69a34c6f7f382dc47d95bb60f97be85d518bf1b5f60e80764bdd56c1880 }

condition:
	$a0
}

        
