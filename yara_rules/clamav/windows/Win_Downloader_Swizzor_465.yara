rule Win_Downloader_Swizzor_465
{
strings:
	$a0 = { 0aebd0ae5b2977c569d764c9c3706ce225620284ba10413acd28cdd3a0387f6510f3ef2881517190490400e6fcaff7ae809d1d9c04050fa6e89ff40637d64c89b30527df38ed53ded280ced49f49fae5a1e2bce64a17034b5b99 }

condition:
	$a0
}

        
