rule Win_Trojan_Spambot_220
{
strings:
	$a0 = { 0e6df59d645d1f5f2f2effa174d286ffffffffd8fe38d84127ef42fb03b38e92a2b0004fb554eb1cad0f47d95c13859e9bd09cffffffffb8f866f479cf4a3dca0f42e0e6ec4ac7f5eba917caffa7a7bba45656e5742b22ffffffffdb36335ba0bc2819f68e0c16638669eae3b8dc }

condition:
	$a0
}

        
