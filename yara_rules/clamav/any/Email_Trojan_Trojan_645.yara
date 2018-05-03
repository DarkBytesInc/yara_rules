rule Email_Trojan_Trojan_645
{
strings:
	$a0 = { 4920686f706520796f7520617265206f6b20687474703a2f2f }

condition:
	$a0
}

        
