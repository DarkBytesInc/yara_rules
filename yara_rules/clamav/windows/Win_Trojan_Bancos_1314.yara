rule Win_Trojan_Bancos_1314
{
strings:
	$a0 = { b853e6df8ed27cdbf95bf94a8041bde7693a145310e2809848bf0246eea60e7f80d38a97636c94901625719bb0ca1c68bcc6961dcf760e73ee3ea53e0a11a403f93d08ad79da9fe54a7df502a126f89960fd }

condition:
	$a0
}

        
