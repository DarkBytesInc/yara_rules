rule Win_Trojan_Bancos_1060
{
strings:
	$a0 = { 608ec8654ed8c253bf8839c617b8dfcb6a407f568ca304af3eaa73de04ac01109656666e1eb470ba58618fba7c513deb8ff6c0fcc47cd29cbb58df9eb69000458a371543712a4d51391d79ef12f7c83d9571cc1356 }

condition:
	$a0
}

        
