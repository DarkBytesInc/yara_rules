rule Win_Trojan_Fakealert_109
{
strings:
	$a0 = { 09b2d865f869544d9c71267caa3d5479dc192fcd4100f370eb81a350ec5bcc79e6a9c039be0a6feee2adcb7ee1d8d45e2db1db63a13c9e8aeb497b85a1abd97be429a3de74abc7ca5369c582c2edd1f12be0ffff72f7a6b16e0d6535fb0d1fb599e71f18 }

condition:
	$a0
}

        
