rule Win_Downloader_270_1
{
strings:
	$a0 = { 04c74827ad5988826c5e50363cb59f6f01b0efa109432f0294407f6e933c390c600606c07f9746b82a1c1ef633ccc2a4baacaa507590f2eeb144702fe0fcf7ded9dbedbe0929e07769445c1e98b6 }

condition:
	$a0
}

        
