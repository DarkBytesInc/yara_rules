rule Win_Trojan_Spambot_96
{
strings:
	$a0 = { 3f8e55f547aa526fb15b332774af6ce280bcf25201e2ba25ffff9ffe9e3df92935f88ad7cf791a0fe9d1a027c4dea290b63fd9b69a9a7fffffff0d2dd55cf0d6b7e353b8bf4184570a334f89326236eebf6f01e48fd54effffffff073b958342d464aee8194a4cc2466c0f5f1213 }

condition:
	$a0
}

        
