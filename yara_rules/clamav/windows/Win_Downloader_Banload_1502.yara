rule Win_Downloader_Banload_1502
{
strings:
	$a0 = { b9a6080ae4217607bedc2a74c885542e011b6e9a6518f635ffd15203094af9d74b14350fc6c99c4117137441733684b746e8dcd4c2afe96ab6537e2083cc4cd813c939fed9c7747f2402d2b6969acda7589453cb6e36c3483a812d54ffee87f915ea8aab33f54d36103e917eeb23210a805021fae6865a50895978cab4d7927896c040278b786441731d8cdcfe }

condition:
	$a0
}

        