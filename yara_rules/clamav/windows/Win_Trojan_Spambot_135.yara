rule Win_Trojan_Spambot_135
{
strings:
	$a0 = { ffffffc30556952ed3b68e617d93b2880ec239c69f35340abca94ba01a05ffffffffd7174347a9e5047cb2c4acdc4ba8c6e4b10fa66b68116b3ada1cb18584d7ceeaff7ff0ff8e9489a52f31401755c4b8c1e32f930ed178a0845c24ce39cd54e1ffffff5042065869eb09c661db }

condition:
	$a0
}

        
