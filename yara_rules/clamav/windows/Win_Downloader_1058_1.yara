rule Win_Downloader_1058_1
{
strings:
	$a0 = { e67e81ecf4062a42b5500ddd3a6c70d587aa81d33db3c24aa05c6e0bdd2e15d232d06ceab2dcb6beaf0dcd72d5e1d688828d8d016560e90851b07d0fe5d072421da0815bd5d138cb6bb7efce783eaa89cb5009b6804f155cb68931b5 }

condition:
	$a0
}

        
