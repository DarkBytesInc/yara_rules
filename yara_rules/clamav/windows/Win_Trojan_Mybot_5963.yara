rule Win_Trojan_Mybot_5963
{
strings:
	$a0 = { d3d669e9f3f59fa94772df0dc0e09fe514cdb8b43950173034daddbce8af3d9fe9c23f03256648666a5538aafd976ea2746840f04ea8391ab19986785bc6fb447716b15e322ad3b9ab1e0ef21bc6688c }

condition:
	$a0
}

        
