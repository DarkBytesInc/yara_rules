rule Win_Trojan_SdBot_3659
{
strings:
	$a0 = { 80314127fe2f4076f8a6e7a9416703f6c1b6669b6e13da71d09f742ef573af8de4ad8485062fa175c0c36974c780f1ca447d8c240b8a771f10a0e258aacfaffc98ec4d1e8fa36b20ef900072a580 }

condition:
	$a0
}

        
