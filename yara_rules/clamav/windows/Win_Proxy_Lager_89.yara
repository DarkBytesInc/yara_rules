rule Win_Proxy_Lager_89
{
strings:
	$a0 = { fd3c6c037b62a935f470f2857afd82078ee12227c8887a899c6fe1b0953a9e02165aa3d029aeb6eb1de1f6c28361a0c18b8a5d28da98231f3255dd961eb730ecbd8f72f8 }

condition:
	$a0
}

        
