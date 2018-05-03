rule Win_Proxy_Lager_45
{
strings:
	$a0 = { ce2731ddd9cb845d001f5c2677303386c0bf7a055eb373e178a18602dc23b4a702c8b99e680dc052a34e1f9c98c7bf0841f0ed3139f38a4bf4b8da32761de9844bc6f62b7aa4 }

condition:
	$a0
}

        
