rule Win_Worm_Roro_6
{
strings:
	$a0 = { 48616c6c6f20526f7375726f68656172742e2e2e0d0a0d0a }
	$a1 = { 4d617263682032302c20323030330d0a4279205265642d4c6f76 }

condition:
	$a0 and $a1
}

        
