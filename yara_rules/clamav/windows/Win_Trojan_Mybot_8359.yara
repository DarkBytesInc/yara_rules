rule Win_Trojan_Mybot_8359
{
strings:
	$a0 = { ec9e85760a48b55790f933d357feef95cd68b726c10c646b9f6a1cbcee404b4f67faedf588eadc78de1588a147099c9a50a07b6dc2f4c9fc2c3155f4f39fe622315bb2e7cf4d2494366f821b4e018e8ca2aee00862 }

condition:
	$a0
}

        
