rule Win_Downloader_Time2Pay_54
{
strings:
	$a0 = { 5f29d3feab947c647ecb4d745bfe5d6848c743645bcb79b1c351d08a4e8a2756b750acc8c39def32ec5c81f6ede75b1442aa1dfa2fd9d07e56ec3d3aeddcc45e606d7a8ad62fc3bd39e0798c791df3b7c3627832e7fea65cc668266c3f6356cf5138e464f3dbff3eed9afdd243d8e27385a9fb6de9c4f9d6177658 }

condition:
	$a0
}

        
