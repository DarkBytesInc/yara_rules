rule Win_Trojan_SdBot_1804
{
strings:
	$a0 = { cc17d90cc6344c253ca67321b4fb1ef01e132c92c70b8a2e1bdc27640c4c06363c43a76cb711685574599556cc592cf4606c46dbfd48417ca651445b68fdfd42c2850da15d2b6a56cf46b0d18a517464304e683456c876d9851c268e42052a }

condition:
	$a0
}

        