rule Win_Trojan_C_97
{
strings:
	$a0 = { 120e2e89160802b430cd218b2e02008b1e2c008edaa37b008c067900891e7500892e8d00e80e01c43e73008bc78bd8b9ff7ffcf2aee33c4326380575f680cd }

condition:
	$a0
}

        
