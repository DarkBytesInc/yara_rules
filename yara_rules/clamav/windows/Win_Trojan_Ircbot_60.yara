rule Win_Trojan_Ircbot_60
{
strings:
	$a0 = { c6c14811755c0c1725e42b83f0c42a7ce7017a609f0b3beb9cfbe69e21c5d83e14ba1d91bdc2f0775563528d0eb1c7164cf6addbba706bb750385fdc26e18ff0fa2060c2b5f2dd59813098fa31bca3f76185848de4d59ac91f784dedf3ea1b714f5ed33123153fd003bca7acffe1ea1cadee413d6d13b01c }

condition:
	$a0
}

        
