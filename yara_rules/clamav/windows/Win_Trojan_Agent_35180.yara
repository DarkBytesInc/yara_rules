rule Win_Trojan_Agent_35180
{
strings:
	$a0 = { 9c33c2f9fde8000000005b90488beb66b871de4181eb311001004749485381c53e000000c1e6396800000000 }

condition:
	$a0
}

        
