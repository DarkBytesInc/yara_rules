rule Win_Downloader_1174_1
{
strings:
	$a0 = { eae67ad6b04b094eb605d9ffe07ee0d7cbfc3442d17705a3cca41b23375a25863bfcf1632b466e6d9ffce2bd02799038fc356de4660a98ec31fc01d88d019581fb488a3700c15f5045edb1b693250070f4ac737bb27d6ed333fceaa7 }

condition:
	$a0
}

        
