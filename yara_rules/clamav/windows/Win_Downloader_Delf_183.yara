rule Win_Downloader_Delf_183
{
strings:
	$a0 = { 686d722e62697a2f73662f626e7463b1ff7f81ed5f312a706220485454502f312e300d0a486f733aa236ec743a20290f74708c0cd5ee112a2f2a0cdbcb }

condition:
	$a0
}

        
