rule Win_Trojan_Spambot_173
{
strings:
	$a0 = { 8edb0bba631cc325ffffebffeff478571b26bb4c9337dbff66924e2042b00d9cb2b931843902ff7ffdffd63c068746d870cf0887ccba95b3731705fd0f00e32672a75bfdffffffff372889d36ed70ae629504ffdc0db0e2aea7f015ce764b353f45f34dd8b8c644dffff3ffdefd0 }

condition:
	$a0
}

        
