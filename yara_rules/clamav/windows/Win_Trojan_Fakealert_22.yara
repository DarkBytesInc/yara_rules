rule Win_Trojan_Fakealert_22
{
strings:
	$a0 = { e25e560152bac61decfb4c9ce105946d5ec9de04cf68d6914ad5cb7872b9d67ec40bc000496c41e792864d1cc40b146d1cc50da55ac5ddb1a4efd5975787d6045f7cc28c4ed8c32db3efcd01a36c2ab2b42e80cf77b34f71525fdb73c4b9a9184f554d71 }

condition:
	$a0
}

        
