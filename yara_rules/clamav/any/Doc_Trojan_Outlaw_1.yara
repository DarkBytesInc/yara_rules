rule Doc_Trojan_Outlaw_1
{
strings:
	$a0 = { 4f240664690247240c678d810569034e4a24126c050006643d69024724076a096c617567682e736372233b34716c01006436716c0100126a0b4e204c415547482e434f4d643671 }

condition:
	$a0
}

        