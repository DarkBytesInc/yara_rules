rule Win_Trojan_Spambot_154
{
strings:
	$a0 = { ffffffff6338bedb919dfde5c5db7eb8e33a26e3dc1caf4e1cd69a42acd41f9d7804d409ffa7bfeb52ee4a08f84cf507ac0e7ac926dad991219d195cffff5ffc7faa805e3ecbbd53257efe164ce6267eaec221cbdec625ab886dfeff7ff5fb2554cfeb1eb47f07ee96ea911099c7 }

condition:
	$a0
}

        
