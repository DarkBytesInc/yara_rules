rule Win_Downloader_Banload_405
{
strings:
	$a0 = { e8f05f02981bc065579666aecf847d95d667c5f51e687be631e7fab978430fe7414d51ccfa583dcefc59fcd5d0dd45ae45ac795a278c03f96ab14d24a85bda6bd2699cb1807086a2b17179dccf731f6c4bda1fd4b7dcfea618440b79b47ab244da83a8fe }

condition:
	$a0
}

        
