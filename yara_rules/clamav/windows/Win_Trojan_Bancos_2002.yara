rule Win_Trojan_Bancos_2002
{
strings:
	$a0 = { 5bbb862ad0cc1fbc1d84a20dccf2dea7a5eab0cae7a56db8210bb45457db3529f6e2da238d4f7da8c95d44872fdb67e5e975b2d9dece6ecb295178230d93a08413c42fa47ffb3fff711202711a641dcc031b633c9a7b8d15ab1e1be414856affc08b31c5b1e4f498aac2106b2834 }

condition:
	$a0
}

        
