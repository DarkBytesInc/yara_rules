rule Win_Trojan_Amz_4
{
strings:
	$a0 = { 1e068cc88ec08ed8ff06cf030633c08ec026a16c04a3660407803ed403ff7503e99400f706660403007508c606d403 }

condition:
	$a0
}

        
