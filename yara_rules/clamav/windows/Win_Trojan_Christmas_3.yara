rule Win_Trojan_Christmas_3
{
strings:
	$a0 = { cd21b301e800005f83ef058bef81c5580389be06047504b8004ccd57bf00018bb6060483c615b90200fcf3a55fb42ccd2103d588b60004b00022c07513b42acd2180 }

condition:
	$a0
}

        
