rule Win_Trojan_Bancos_1733
{
strings:
	$a0 = { 9522e1febe71bb5b7cceaa32f02a9612a26f10b19390bc396f134e2f70e1d7e7b6bf790bf9f7e56317a310a7bf32900b52271002db06e440e6f1d98e7a33e8e6a973fa307580 }

condition:
	$a0
}

        
