rule Win_Trojan_Bancos_1319
{
strings:
	$a0 = { 113f52608c113bbcad043c2064f815bbde611794e5826cc41386db209e5d6350d41e5368a18229c9a92f6a7fb12742ffb2d98eba9a9bd70bfcc0c643dfc42c3d58b2a9e11857f8e54c8964e68167753e86bddd3d }

condition:
	$a0
}

        
