rule Win_Trojan_Am_1
{
strings:
	$a0 = { 5053515256571e06fc1e33c08ed8c41e84001f26817ffe616d7403e8d7012e8b36010181c6fe00b90500071fbf0001 }

condition:
	$a0
}

        
