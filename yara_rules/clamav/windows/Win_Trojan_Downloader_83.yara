rule Win_Trojan_Downloader_83
{
strings:
	$a0 = { 61646f64622e73747265616d[5-200]777363726970742e7368656c6c[5-200]7368656c6c2e72756e }

condition:
	$a0
}

        
