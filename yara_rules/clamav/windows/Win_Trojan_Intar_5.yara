rule Win_Trojan_Intar_5
{
strings:
	$a0 = { 60e8000000005d81ed062040008db5242040008bfeb9580400008a06463473880747e2f6f8f631533373fa }

condition:
	$a0
}

        
