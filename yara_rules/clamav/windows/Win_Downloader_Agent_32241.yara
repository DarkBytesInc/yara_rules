rule Win_Downloader_Agent_32241
{
strings:
	$a0 = { d22ccd1d6116643a17448d41df7772fadc3ec122e7eac0d815faf68cd6449c2836385931b6a5d9ce1e9c2800547cdaf5053cd9132719faa90f473d2872adfd6001b9685051bd23b134db188feb9b1f50815484c26c55601aa38e6c1b62173020f1293e06ac1a60f9b219575a4431ea1537ca4359e8206c724c38b6831a712162e41971d2cba46374b241033f3ececa3adbc8a546 }

condition:
	$a0
}

        