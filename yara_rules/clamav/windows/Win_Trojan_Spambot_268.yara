rule Win_Trojan_Spambot_268
{
strings:
	$a0 = { f8018010c9a03eab259a3a62114b17ffffffd1ec3f95da99e6c2252f5cc33a25a3757c40128ef9d4caf9fd56e0ffffff734e3cd040e0742b2905eaf45ca347a60e0d37146844f3aea31de8ffbf16f10d6daf015a30e3e0c779865c5c0b7690ffffffffa4ec5e17c57dd20b6d94fd }

condition:
	$a0
}

        
