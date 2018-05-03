rule Win_Proxy_Lager_56
{
strings:
	$a0 = { efea12b7272a4cba09814abf77e876b06f9fb56d4b94cecdb2ebad9dffaeabb2101d21cb9f7158dd8aea9aed0118fb28c33caaa5c73aa32b83a44f58e5a17d73ccf5859dfc30 }

condition:
	$a0
}

        
