rule Win_Downloader_Small_1557
{
strings:
	$a0 = { 48eb91ff3307491722092d44374f898b140a60db084f6c1d510dcc09f9f1e3a67c29bd360838530107616476361631101c53 }

condition:
	$a0
}

        
