rule Win_Downloader_Banload_1011
{
strings:
	$a0 = { 52076fc92157bcb8d53f47a623157125489fdbb38658ae8a829c79a66cdfad14fab14668d3c3676765b34ed9354f01cbb8612c12cd5b9ae73d0a6a25c640e3ffb80cce55e8e0fa5997d6e64109c6356c }

condition:
	$a0
}

        
