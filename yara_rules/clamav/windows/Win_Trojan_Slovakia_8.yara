rule Win_Trojan_Slovakia_8
{
strings:
	$a0 = { 737481e06973027a20845b204781e861630220ba17064381e86579bd58ee3842653a414f4b3a7b2043432a0281f5 }

condition:
	$a0
}

        
