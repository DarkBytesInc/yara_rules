rule Win_Trojan_Hupigon_319
{
strings:
	$a0 = { 0ad6f3fc73615ac5edfc593194bd46bdf0af3d9924b7e49b69bdd12bfc49fb92c5bab47306e969d70156b71eda68e1b864c60b6acd1b868aab0abb6dbc88a3b63ffafdecc49859875e82db64d71bf7417a2b9ce50ccb770ac3e1 }

condition:
	$a0
}

        
