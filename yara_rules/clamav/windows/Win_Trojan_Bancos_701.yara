rule Win_Trojan_Bancos_701
{
strings:
	$a0 = { 6d0c523a8def39d384999ce25e3eea144a44ee90bcde41a929569b457c4519515588197e440cb60f4e432e508dc8e235bbf4cb26b2da239f8f1380690ec33733f99fa9f3c58196293aef1d35 }

condition:
	$a0
}

        
