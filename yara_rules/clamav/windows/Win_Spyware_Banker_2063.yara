rule Win_Spyware_Banker_2063
{
strings:
	$a0 = { f8a350ad3097d8427366cbf7a407d9aff6fa21e9e95da8bc86bbeae4f9ac2bebc50a08f176b42fb40ddbfaa90bb4277f6bc64aed4f9b9c948463b3f6db20f18efdd1d7f6c0bff9d593e6c5d8fdde10c740ae2ed8efc7f6c2992c7dcb2d32f6079653702fc0518892348abebd28c975eee252 }

condition:
	$a0
}

        
