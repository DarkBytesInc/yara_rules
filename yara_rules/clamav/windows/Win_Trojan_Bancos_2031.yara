rule Win_Trojan_Bancos_2031
{
strings:
	$a0 = { d2e5de8179cd639bbe32b8d11d75db3b1f10399bb52e8d7fe5d58f402948abfc2cf8d9fb96d26df64508efef423b4aebfd3107895a0239cfe3970bbf8db24b00b7b24608bce6363ae06cd8b769248a3d818ec33037e83a8efe39f01f74cb746c78ba909ea2efa11493134e5bc88c }

condition:
	$a0
}

        
