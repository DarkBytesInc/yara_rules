rule Win_Downloader_Swizzor_459
{
strings:
	$a0 = { d61ee13c391bac3cd847fce69aba4335f58500d570d37be2f13a0f446a4f26b3f343c52c86c05f135d9f91ef43e6cdf95875802055041baade1f3eaa8796dcc9c58c3574ce07b26722a23292f2dbc60796bdb7b2069783861c85 }

condition:
	$a0
}

        
