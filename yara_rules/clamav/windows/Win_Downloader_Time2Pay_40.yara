rule Win_Downloader_Time2Pay_40
{
strings:
	$a0 = { 460b06ffb2b6a96567e9987542dc886951e5966542e9acb0da73058b57a8f257ae7279c9dabf3a33f57e54f7f4c58e155b88c8fd36fb057f4fcee83bf4fe115f794faf8bcf0d16b820c2ac8d603f26b6da5cad33fedc735ddf4af36b265d8dd2481a3165f6ff2e3df0be2cd758fa37729c8b226afce420db0e508f }

condition:
	$a0
}

        
