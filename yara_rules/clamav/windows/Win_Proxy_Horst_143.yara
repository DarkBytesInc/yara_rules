rule Win_Proxy_Horst_143
{
strings:
	$a0 = { 58ba401fc997dc50ba4058ba4050ba40b3857c2458ba405f3e84a0dce91d5c4f9cba40a2a918420d77b8135645a77662c05d917cc9b140c0b140f4d97edd48edac85b804eb330ca8a27796e7a826b0047b87fcab6268ffffffa41a04f99055d162d1b2ffff7a1f4500f3250579e4b32a6244b24044b240e83c150bf50d0be4cbaa62c8b140f9e481e444b24020b94044b240f257 }

condition:
	$a0
}

        