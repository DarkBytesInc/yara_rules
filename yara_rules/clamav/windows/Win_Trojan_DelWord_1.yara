rule Win_Trojan_DelWord_1
{
strings:
	$a0 = { 126a0e476c6f62616c3a5061796c6f61646467c280673b800506076a103a537465616c74684163746976617465126a16476c6f62616c3a537465616c746841637469766174656467c280673b800506076a053a46616b65126a0b476c6f62616c3a46616b6564690f537465616c7468416374697661746564 }

condition:
	$a0
}

        