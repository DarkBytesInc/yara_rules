rule Win_Downloader_Banload_1740
{
strings:
	$a0 = { c63ed3ab941d81a3537cd3fde7fae90876f05a12272aaac9ebd446d1a87c75356db458e992a3605dc3394b07d1e7175a6fd03aa610aebf69d1e64d6c5be01ad93ae578a98b9a0f766d89c791b9ec98ca17fa25310416bd1cf2ac0dff2d7d378ca02a7bf5456c7c3988f96f90fc255daae95cd889d80052b274bf8a7235903c8349d7606b582d6bd39a2d7894 }

condition:
	$a0
}

        