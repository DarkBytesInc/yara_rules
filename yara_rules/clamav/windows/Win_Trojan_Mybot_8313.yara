rule Win_Trojan_Mybot_8313
{
strings:
	$a0 = { 511f357ad8e4fa3d506781108ea1bd8a5f2a89226eea9ef0fbef1efd77137e218b9ff1fc4167d3acbc5c53ec5dee4a7b5bce95d8b3ba9adda2a242ab2bd97a991323d1b2d678799845b6cb21c7a77831c7a94d8fc6a6673e0246f90671fe59fd1e33f305 }

condition:
	$a0
}

        
