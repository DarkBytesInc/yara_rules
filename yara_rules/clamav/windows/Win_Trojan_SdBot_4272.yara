rule Win_Trojan_SdBot_4272
{
strings:
	$a0 = { f41103920041e166bd13c9ed2e89abdbc14cd6d919f889c67c174f1934db8eb8dbdb88eb674f819ef9bdf4ec89241870b99bcf53daacd0c66dc5b86d2c260d5148b0f6206cad0b0ae4d7e6f89f1f6d635f537cf5eeaa01a07b22ad368c860c8aec8b997e3e9160a13d2f978d3bba925cdd46b65b1abd }

condition:
	$a0
}

        
