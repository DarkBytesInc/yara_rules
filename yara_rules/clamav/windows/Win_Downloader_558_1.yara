rule Win_Downloader_558_1
{
strings:
	$a0 = { ca5180cab3c68586f9ffff3380ce2380e91ec6858cf9ffff0080c6cbc68581f9ffff65c68588f9ffff2ec6858bf9ffff6cb2235583ec048dbd80f9ffff893c2480e12c80cebdff15d8d001105d898544faffff8b8544faffff8985e7feffff80cdb6c685d2feffff73c685d1feffff6580f6d6c685cb }

condition:
	$a0
}

        
