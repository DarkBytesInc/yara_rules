rule Win_Downloader_265_2
{
strings:
	$a0 = { 2db85712fd861021b5ca5782e7157cee11d1f93862a643e807f4bc07e56a86191cd7c8aae8931d7b07db6818f822094b96c2e41aaf9bfffe2984a9b680daaebb2c77c3e74229467d6a78bddc855f }

condition:
	$a0
}

        
