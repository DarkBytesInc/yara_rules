rule Win_Downloader_Swizzor_387
{
strings:
	$a0 = { 4eb42faa28f51e655fde7ff15382123995ccea57e988c9f23b696edda5425d4533dcc6db3d2b59cbd67f56d2d0797433a2e8e31833e93c4c017f2ff44da9d53496776fd8ec87834f4073ce2df38d425e96b766063fb8b1ec0551 }

condition:
	$a0
}

        
