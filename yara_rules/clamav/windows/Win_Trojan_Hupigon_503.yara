rule Win_Trojan_Hupigon_503
{
strings:
	$a0 = { 574f2443c17468a83a216740a4d2925d190baab7b45838715fbfa6cec9a4e6a1960d8288df1e27494c6c896495d510ff7f89a787e19ab66fc57c8c72c0f0db6e4bf7b18be35775562fa3480eeec9 }

condition:
	$a0
}

        
