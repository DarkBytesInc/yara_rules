rule Win_Trojan_Mybot_8368
{
strings:
	$a0 = { 7ceb99ad3a30a1c89c1c7df01724c5a97e91d7994c199e1d67ad1c2ed5eca8fbd5d258a99ff4bbe012028c2c589a0250c658f99db12369319332f89cfe531ee157a852631d985c28e010f39d784bdb794ceb120d8e }

condition:
	$a0
}

        
