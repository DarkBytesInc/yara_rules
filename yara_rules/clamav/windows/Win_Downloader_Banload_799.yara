rule Win_Downloader_Banload_799
{
strings:
	$a0 = { 1b75e84fa20be7f0e06faf85370ba52667a961b5d66d755f36bd2ad8b7fa2eaca446f3889412dc3a27f66b0a1e65e3e72710a87f68c63e080942bdc6391a12067acafb731eaaf7bd72e521b0de7fa4dbd55d20baad68b1d8c764a6f9b949ad0ca1dc9ee3 }

condition:
	$a0
}

        
