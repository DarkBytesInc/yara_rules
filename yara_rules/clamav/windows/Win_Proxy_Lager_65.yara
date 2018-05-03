rule Win_Proxy_Lager_65
{
strings:
	$a0 = { ee21b5f1ed4bf5a37fc82deefdaf18263df1150896f71076ffcb1f6e8808c24a837362b3fc1032feb9161d110a9c649e66e5728bfd2742000f4687c22b170ac62d1e8482b3f2 }

condition:
	$a0
}

        
