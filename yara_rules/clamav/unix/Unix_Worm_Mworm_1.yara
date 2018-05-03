rule Unix_Worm_Mworm_1
{
strings:
	$a0 = { 8d8d50ffffff898dbcfeffff8b85bcfeffff0fa314030f92c08885c0feffff80bdc0feffff00755b8b4dec898dbcfeffff8b95bcfeffff83e21f8b5dec89dfc1ef0589bdbcfeffff8b85bcfeffff8d1c85 }

condition:
	$a0
}

        
