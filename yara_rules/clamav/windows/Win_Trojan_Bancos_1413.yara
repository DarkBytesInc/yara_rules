rule Win_Trojan_Bancos_1413
{
strings:
	$a0 = { 76f423f05e9b7ab65b81c0a1d82f94cd88d2c8aa96377db4f90882f6b43e991afec82f9f227119ec63bbb7df0804ab4d2b5c22b802913e7ec8ddb5b9ff40f93e7a9c25ee8cf38be08a4836257d47f8e954c6c7f0b446f3a8be3e }

condition:
	$a0
}

        
