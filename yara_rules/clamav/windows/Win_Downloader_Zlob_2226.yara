rule Win_Downloader_Zlob_2226
{
strings:
	$a0 = { cf7c5288426c141413c596f189af387b1db92b6a7d50cb9c085e4855438893491fdb446801dd61456a7f84cd201ce24bb923a27f7aa455c2ed6f40ecbfb24923c8c3db79bb0b1e5763fa9a50871fef49a0b4 }

condition:
	$a0
}

        
