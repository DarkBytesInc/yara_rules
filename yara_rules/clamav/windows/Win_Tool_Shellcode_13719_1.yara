rule Win_Tool_Shellcode_13719_1
{
strings:
	$a0 = { 31c9648b71308b760c8b761c8b068b68086811111111666811115b53555b6681c34b85ffd3ebea }

condition:
	$a0
}

        
