rule Win_Trojan_Hupigon_314
{
strings:
	$a0 = { bbcf3f8c9e4bd443e9792b0863faac72f6e1b94fcedc8484078904d8b06a258dae0829a16fee7d1ecd2ad821aceb5593f9049a129764e0bc5caa8ddb1f386db1863186e4191dcd50296a040456e97336b090d87de4936c3eba96fadc257ecc0846b2ba1628d1 }

condition:
	$a0
}

        
