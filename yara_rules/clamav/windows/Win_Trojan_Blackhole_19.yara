rule Win_Trojan_Blackhole_19
{
strings:
	$a0 = { b101baac6d41008bc3e8bdbeffff8b4df88b55d08bc3e8f4bfffff8bc3e871c8feff807dde00742f68400004008b0dc47641008b098d459cbae46d4100e8edd5feff8b459ce899d7feff5068f86d41006a00e898f3feff6a058b45f8e882d7feff50e808f3feff }

condition:
	$a0
}

        
