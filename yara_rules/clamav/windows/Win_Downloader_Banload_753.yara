rule Win_Downloader_Banload_753
{
strings:
	$a0 = { d43c50ac426e69f0a2c53a8418d410b62fad686e0986f7ae2b709d5ba356a058a70345a660d9fe54ab306271f71bc87900d9051a9cca316de8f1885d7472e0d159984f9f8824b073e44cbd9934bfca324b5bd682b97c3d2426fa }

condition:
	$a0
}

        