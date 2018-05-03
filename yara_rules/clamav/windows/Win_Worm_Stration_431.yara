rule Win_Worm_Stration_431
{
strings:
	$a0 = { f3b319c737f809c4f9b251ad7785baf337b41cb7f06f4b3ace94b936f0586759cc0c296e95329c74ea646661c719ba9a5f463ce9b67df8898225a85ae7cb157c0f4c5413ffb888a1545624a821df9cff }

condition:
	$a0
}

        
