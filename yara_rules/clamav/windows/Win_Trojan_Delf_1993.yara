rule Win_Trojan_Delf_1993
{
strings:
	$a0 = { 9a7e20f034df9dc781d4cd9851dccf59c1baf96485c5ca46ce5eca9dd3a40445ed54352a9e3c950a2b62124a5fd0861b8a8c888df53ad2690025109ef7a5eb3d9332dedd4da912ef314ef4627a411b52879e74cfd8311abef4c80c542c3acf347a5aad595981c889fd4d621e7fb4371d6dc1666e2da0ab2b9a11e0 }

condition:
	$a0
}

        