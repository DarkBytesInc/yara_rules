rule Win_Trojan_Bancos_1014
{
strings:
	$a0 = { 4412dae8e7dfb9db01bd651e0f4165190c954dd4805c2c22a9aeb78492fe92605e6e0c6ff9fe1d9d08a02eec7abcd9aaed84890ff994c0232521cc7b38cdb64c324a5bfb5c4e39c7515e52eb6974b80dbdbcee4c2c2149e6 }

condition:
	$a0
}

        
