rule Win_Spyware_Banker_3435
{
strings:
	$a0 = { 5036821de65f48a14f9e7ecb9b6546e5955de2dd7ace869b70e9b8a873ce5b6a3881faee1ce6718ed36743b2265a6f87094111574affdce98e9af275e141755d74a14f2fe9964a9ef0b43ed2a51fd87ea857c8c3ddb5b5772fb23d19c226fa }

condition:
	$a0
}

        
