rule Win_Downloader_Banload_1896
{
strings:
	$a0 = { 9d189834949d9d9d9d8870506c9d9d9d9d1c04a8009d9d9d9db87c385c9d9d9d9db4b04c149d9d9d9d487810a49d9d9d9d3c58c0809d9d9d9d20acbc289d9d9d9d8c0c08909d9d9d9d6824a060e09e9d9d44549c3816c60268541fe8027e1e374b3b3040ebf800007ab6c09c8f9d5b4cbf3846b6f77792fd01380b7d0050726f6a65637431ffcc0100000007 }

condition:
	$a0
}

        