rule Win_Trojan_Bancos_1815
{
strings:
	$a0 = { 405ab2b57cdcdd479eb43821eac011aaf478726211d2ee1dd2ae0c106202e48af3e36a387a2941c8cd0f3d5da5d7903dee3137900784328ba3121b8976246d04499cd4a52ca8 }

condition:
	$a0
}

        
