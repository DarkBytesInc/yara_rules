rule Win_Trojan_Bancos_1831
{
strings:
	$a0 = { 008771d39d53fdd6dbb63e2e413c4750d0733c193a535fedf021c7b80e3a3e4fd5200337092878c74f57d2fbea62e7766b3b8377ac3868e44bcc24086470cc63e490ca7f30bd }

condition:
	$a0
}

        
