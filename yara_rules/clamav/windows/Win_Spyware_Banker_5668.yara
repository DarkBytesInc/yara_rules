rule Win_Spyware_Banker_5668
{
strings:
	$a0 = { 3d156ef1dbe29cf1a5dd511aebbd1912feefff1b0e3f78acf1f071caf7abbf6e96daaa6a5d6cfcfc011e4cdf40619d343b5963380106a3d5dfd99c10512305e782feffff253d33e8fcc9df6e1bd72c9fab7558fe8faf5e5fcc177fffffff01fef9fff607fd67d830f7fdbf292723f7293645fe1bb467c53cffffffffdf593d7a }

condition:
	$a0
}

        
