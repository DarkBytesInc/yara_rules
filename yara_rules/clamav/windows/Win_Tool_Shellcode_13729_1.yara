rule Win_Tool_Shellcode_13729_1
{
strings:
	$a0 = { 31c9648b71308b760c8b761c8b368b068b6808eb205b53555b81eb1111111181c3da3f1a11ffd381c31111111181eb8ccc1811ffd3e8dbffffff636d64 }

condition:
	$a0
}

        
