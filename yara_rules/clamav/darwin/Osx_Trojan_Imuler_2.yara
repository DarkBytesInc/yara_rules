rule Osx_Trojan_Imuler_2
{
strings:
	$a0 = { 4375726c55706c6f6164 }
	$a1 = { 6c61756e63682d[0-62]786e7461736b7a[0-177]6d702f786e7461 }

condition:
	$a0 and $a1
}

        
