rule Win_Trojan_ANSI_2
{
strings:
	$a0 = { c4b420b320b320b320b320c3c4b420b3b3b320dedbdbdbdd1b5b3130431b5b33376ddfdbdbdbdbdbdf1b5b33336ddcdcdcdbdb201b5b33376ddfdbdbdbdbdbdbdbdbdbdf1b5b730d0a1b5b751b5b33336ddcdbdbdbdcdbdbdd20201b5b34316d201b5b32431b5b33373b34306db31b }

condition:
	$a0
}

        
