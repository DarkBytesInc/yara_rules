rule Win_Downloader_Banload_165
{
strings:
	$a0 = { 45e4d642d52eb940e450b2701113e0e05abc40062545dcc8181497dc6e089a886b3b54b1719d7d81d8d8830bda70a1acd4b98c8eeb3caad4d0d06d5cf2a2ccccc74a870ee980254e313dba09ef6b644e24ff0080ec152d7474703a2f2f }

condition:
	$a0
}

        
