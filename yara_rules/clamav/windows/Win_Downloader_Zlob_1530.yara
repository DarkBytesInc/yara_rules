rule Win_Downloader_Zlob_1530
{
strings:
	$a0 = { 677e2ca60fdb805decb37506c2757d4636649c3d6510f77bb6a6507a31ca5f555f5966802db4ab7df53d9ec23c1747f26322b6382ffd14d70ddfc3aa9acbb678e881841007e5e5a9f83ad01babf73feac571fdc9b9 }

condition:
	$a0
}

        
