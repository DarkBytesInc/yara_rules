rule Win_Trojan_Hupigon_531
{
strings:
	$a0 = { ee54bab46e05e74fc4ddb36655b756f1863e2c53b88f740d35f5ac8626b270d465e2fd7a45613287c265c40a5c3efe94bca95ec6ffc09620c01e2fa2005185bbd388a665992f70eae3098463e7e6 }

condition:
	$a0
}

        
