rule Win_Downloader_Zlob_2282
{
strings:
	$a0 = { 84454a5c1ddbad289e80d06766f07322be9ee22fb1cb104a4f1dc084a4de9027f971f2f13d35698af2e3b3b3af280c4efa54ab4a5f204aba932c8377f550fe594c24178d7e303613decddcb4f8abaadec941b8cca61e764b3a12 }

condition:
	$a0
}

        
