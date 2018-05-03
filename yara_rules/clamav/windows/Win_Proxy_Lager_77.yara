rule Win_Proxy_Lager_77
{
strings:
	$a0 = { 680b554fa6020fc32d210b130d9665f7c00a1fb8912a6b148d2c091bfb84f11891c4a38a121cee08752926c82b2408632d21760a112e6e7dd2f34a76a953b309ca03fe4ccc2c }

condition:
	$a0
}

        
