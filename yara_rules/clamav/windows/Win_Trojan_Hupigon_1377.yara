rule Win_Trojan_Hupigon_1377
{
strings:
	$a0 = { ac2337166e17e0ac9dff87b841c4467dba5c2abd21d9d5a25a5af7af7589f9566fa1c5c3c0151a8c4ea2be140b67a8fa94dbe1afebd7dd9e53426fb535c0e8be4b2653533f556b271ae6ca86654f2f2b3f9abff9adad94597472e074c7e7948ea0320e3e522ffcaa06db0b8364d0216308c07f828abe }

condition:
	$a0
}

        
