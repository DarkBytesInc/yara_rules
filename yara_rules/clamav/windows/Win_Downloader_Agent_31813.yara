rule Win_Downloader_Agent_31813
{
strings:
	$a0 = { b8a39836ba31d077ee5296cb1fbad87b11c1cdd1022e954ab1e55ef61ca993cbb3e691cbff36a81ba915ca9cfb17e5c61dd39a9efb0525c8d044104c0140c79a3dc85340ef1ddb94e51fdb7c4cf47b89a65782c8a05de87be9fd80c8f61a }

condition:
	$a0
}

        
