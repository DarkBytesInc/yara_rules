rule Win_Downloader_215_1
{
strings:
	$a0 = { a3e8810010a160740010890de48100108b0d6474001068e90000006850740010c744241c487400108915f0810010a3e0800010890de4800010e85a160000 }

condition:
	$a0
}

        