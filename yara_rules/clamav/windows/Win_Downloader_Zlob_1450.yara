rule Win_Downloader_Zlob_1450
{
strings:
	$a0 = { 069872f6a28dc0165c4505a89263a9ea4fb1cbe630df8e95b42ccc4f4621183a46098b4de0973f3a87493e12a6298c0eed413a9ca1a163d472544a929ac9b679b8ab6aaa618783505932ffc9f665faf5943ea97877e61181ddc3ca090bd9f44a9d81ba014f115bab40c6bb1b2dcee310b33f6295662618f1b20966 }

condition:
	$a0
}

        