rule Win_Downloader_572_1
{
strings:
	$a0 = { bda7f6ffff897c2404ff15565501105d89852cfeffff8b852cfeffffa3f254011080e266c685ccfeffff6c80f526c685cbfeffff6c80f5d7b2a7c685d1feffff7280e506c685cdfeffff5480c9f7c685cefeffff69c685cafeffff6980e24680ce46c685d0feffff6580f672c685c9feffff4bc685cf }

condition:
	$a0
}

        
