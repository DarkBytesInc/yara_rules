rule Win_Downloader_13399_1
{
strings:
	$a0 = { 5eb44465ec6d53f55d495b3337699eee7decaf6e54fb4834408b6548551b584229ef3baa77ac33911bd23c6e0575ce6fcebe7827b10c0827aeb40c1aa9ca5af0d34dc14ef6a888fe4e96c4aad1918244e437abb4b8f4ad00768fd221967bde5cffc008a6393d508952518f4f4b2618226324b87233b28f6b301008ff1bf28b82cacf020873b4c1528e78e9e2b8a2cdf6 }

condition:
	$a0
}

        