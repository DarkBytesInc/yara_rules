rule Win_Adware_Agent_36730
{
strings:
	$a0 = { 48c804bcf4c7a5a1188016687474703a2f2f7777772e626f616e636f702e636f6d300d06092a8648 }

condition:
	$a0
}

        
