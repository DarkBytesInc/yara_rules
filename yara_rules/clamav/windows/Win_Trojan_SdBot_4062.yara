rule Win_Trojan_SdBot_4062
{
strings:
	$a0 = { f46804b5276fc4c258576a5cdee20a2f22b7802fbbf22d02ea8c35cc5733447d90abe6e80fd9b5beef464d4cb18271bb62018120734f27d5cd2f974f4e0a4e4a1ef6a0bbd31306eecd179e5782d4a0471834a2c71353 }

condition:
	$a0
}

        
