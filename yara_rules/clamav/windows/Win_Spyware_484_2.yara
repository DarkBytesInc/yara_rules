rule Win_Spyware_484_2
{
strings:
	$a0 = { 0eed11ee0eec13fd64ec7b8552a76cfe0cdb31fa77120e118c6a4aed64643e150eed11ed9b988305b6dc7bed9b98830512dc7bed9b98830506dc7bed9b9887053edc7bed0cdf32fa7705a7c264ed13d0ddf9688566ed7b6d8c9a4aed6424b8b8ef01f82988bb2cbe35066aa00d9f1a83008c5ba427bc5ba926ed61ede9a88bbd }

condition:
	$a0
}

        
