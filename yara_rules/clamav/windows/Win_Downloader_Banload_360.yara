rule Win_Downloader_Banload_360
{
strings:
	$a0 = { 0c96f02124bcb41b62c902900da2dec6ba4e6e9921d3840891ead7c2b4348983c55fa1e09edc728101aae5a9e90339ed431abd081437713bfb4d843aee54ed43e803e2f8c31601fac9bc1317eaf517af2092f11b6a3d2a359e5d75a766feeb0870e3def0fec49966af }

condition:
	$a0
}

        
