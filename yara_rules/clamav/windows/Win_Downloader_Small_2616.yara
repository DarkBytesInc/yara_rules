rule Win_Downloader_Small_2616
{
strings:
	$a0 = { 0d05df2b6743ceafe7a174fcc8ce7c07347f2b18d0dbfa686188ced227d9b1b7fe91f7f4599d59656243e8de6ee6c1d9a69ebe5f339147267730f6fb62afc65c164ab55eb5fc56cfaeb09bd1c7eb8e07d4e67f624373a5dfe12299f2ba3696363a21f37c9eefb62f156c1a94604bebe9fad23fc39b03eea8244f0307669ff1fd51b0af54a5e81ad8038d39b9d722081d09c80df710ee }

condition:
	$a0
}

        