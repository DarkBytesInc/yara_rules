rule Win_Trojan_Netbus_30
{
strings:
	$a0 = { cd167d6421dd8ae438247366b633fa4bf26c392be0a5fa0d69d2bc3ae02fa807d56b55a9414e179e459978bfb5df1dff09d7ed4140a27e0d3ad82e2a2972c76d4453134746add64dd1aa84b6faed3d2c90ed6fafb33ab01921fff37c86b659fbcb51e63b }

condition:
	$a0
}

        
