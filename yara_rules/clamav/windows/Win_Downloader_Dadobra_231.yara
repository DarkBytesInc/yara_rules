rule Win_Downloader_Dadobra_231
{
strings:
	$a0 = { e41c7fa2778f223caed963a7c3ec11b82fb15f792dbac43bc72dfb50185b50a9c1612e72e0dd1d822b0a00d7fad0fc39c84d44f2845ef961835cb349581bb041958c75533196f7efed9d5598c7dd09357f1581b234eecf4c12b44f677b2fbcdabfd7c9d2b49087febb7b3e4f }

condition:
	$a0
}

        
