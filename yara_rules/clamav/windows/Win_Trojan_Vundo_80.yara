rule Win_Trojan_Vundo_80
{
strings:
	$a0 = { c78424d4ffffffe17d1948d24424d6d24424a00f1e06eb03c7f41dd34424e6c14424e492d24c24d1d28c24a5ffffff886424a481e9de40c0f3e80000000068000000008f0424091c246800000000091c248f042468de40c0f3bb00000000031c2483c40403cbd28c24e5ffffff89ac24c2ffffff81ecfcffffff319c24fcffffff898424d5ffffff887424e7 }

condition:
	$a0
}

        