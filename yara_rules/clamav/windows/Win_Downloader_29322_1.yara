rule Win_Downloader_29322_1
{
strings:
	$a0 = { 761200008612000096120000a812000068120000000000000000000000000000558bec83ec334c896de0608bdcff15101040008be3ff15001040008945cc053f104000ffe08bc0c745ec00200000c745f415665f20c745f826a9cb138bdc8be3b8a4104000250000ffff8945d00345ecff70748f45f08d80880000008945ec8d45fc506a04ff75f0ff75ecff1508104000 }

condition:
	$a0
}

        