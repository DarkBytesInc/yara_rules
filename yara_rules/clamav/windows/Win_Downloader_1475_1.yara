rule Win_Downloader_1475_1
{
strings:
	$a0 = { f1cbca79c5c5c5843a19f1cbcac6c5c5c51b843a2df1cbcac7c52d8af6cbca2d615dd8cabcca6df8cbca552d614bd8ca2d615dd8cabcca6df8cbca2d31f1cbca2dfdf1cbca2fc52fc52f392fc52fc52fc52d615dd8ca2fc5bcca2df8cbca2fc5bcca45f8cbca154c3a594bd8cabcea594bd8ca1d48bdc03cf1408439554084c9bc34fd1d6041f1cbca2f052dc5f5c5c5bcea41f1cbca }

condition:
	$a0
}

        