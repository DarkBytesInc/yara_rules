rule Win_Downloader_Banload_1550
{
strings:
	$a0 = { 8a65ecb181526c753c6512a6f1a7390bc4eacf460b318284322e3d30540ccb5e365dedfce0821ab8992f75c812e90eec7c9dc5f966842a57b0346c38582b3ecc8b0042c4b4c6af07edf3fc0b3da6419951b9cf32a7beb98a0873 }

condition:
	$a0
}

        
