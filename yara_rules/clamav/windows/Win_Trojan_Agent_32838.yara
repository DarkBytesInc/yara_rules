rule Win_Trojan_Agent_32838
{
strings:
	$a0 = { ea9d7e14fff6dcb035e558456f8b8262832adf44247c83b17ffa596bbe790f8a16e3c22359291d9b32b65d9ca2961531bded5d476372f5a6b58012c8931a79c60a }

condition:
	$a0
}

        
