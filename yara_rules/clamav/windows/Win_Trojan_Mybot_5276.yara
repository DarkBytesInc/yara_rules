rule Win_Trojan_Mybot_5276
{
strings:
	$a0 = { 23354175df71295756ecea11c4ea8f1e132be4e6d4f970c662d8ae330678653b61b4720fa243a8f11319e87d35414a352803d7188f43f146889177aa55f4fbd0be788a962b536dfc17f0b2b37543665e1299b047c5c9791660a6822981be5caca485f10e8329cdd7467d641a4945d18deb6e03a2da07fb34fc0e33b6a8d48ef0fc48e30b9e104ee63478 }

condition:
	$a0
}

        