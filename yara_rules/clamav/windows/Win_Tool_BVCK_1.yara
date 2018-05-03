rule Win_Tool_BVCK_1
{
strings:
	$a0 = { c2fe626c4243564b206f0000f207f25000d2007950003ce00080ff0284126aff9a2af60500046817fe6856009a0919de }

condition:
	$a0
}

        
