rule Win_Downloader_Banload_506
{
strings:
	$a0 = { 86e9214a2e1608bbdf485f7704e3e7eb2f4e5f35fc65d9c360a9e19788dbd4783c39cbe9bba9d44f6a8a1a105ff3dc93ae39f32eceba8452a5f101f3d6c97a0898e1564f8854df90654b3f190208884b568ea0f442e271c25c7bf9f5cf18c587da007733175783d35c30916de3ff1723c6d79c60b3d04e56ae29d601822736177f77c067d749070c17160e82df669b5c139cd013afdb }

condition:
	$a0
}

        