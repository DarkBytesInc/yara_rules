rule Win_Trojan_Spambot_249
{
strings:
	$a0 = { d603b536fcfffffff22db1f84edcfd4bd6cf94d23f74296bd08ad70c00e350a56edc531b1c5affffff1f9578357b7ed8e26d365dd9f5fcc6af138a7f76ba3aa544a0a61ccd3efff1ffff7f353bc46e53cc3e70d594a8f00fd3e85621728385d7f850a0eb84f5ffff228e76a9ed83 }

condition:
	$a0
}

        
