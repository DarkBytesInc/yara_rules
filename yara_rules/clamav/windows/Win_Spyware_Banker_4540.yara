rule Win_Spyware_Banker_4540
{
strings:
	$a0 = { 416eb1ea8ebed7f477221781d7659ec560b3a2836d56d6c4a8b7a436b9d4152c50943c93c362fb516867c4832dc749c36f5c369c8575f77b87c312352d7c0dd28e8fd132624839fdbd6c7bee122b178d00b0d3954092de93146f1b0a892f594da1931e22 }

condition:
	$a0
}

        