rule Win_Downloader_Small_2951
{
strings:
	$a0 = { be07e65880c156c6d3752845804b043439c9b83befc43ad75cf509d8d683bae5c6169b9973e0d13e2fe106de50854b0d03aa380abf9ee4acd5f416816a04291c85840a2dd2883067e1fb1d264ccc6e53d9e501c3dd82896ad244b5b2fd1d556769cd998321c1b2cb555914d655d532bf655f }

condition:
	$a0
}

        