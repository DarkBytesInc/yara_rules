rule Win_Downloader_Banload_1901
{
strings:
	$a0 = { 4b419a5202afa2fb16abaa8cf458637432effd9ba2e07bb4f57e05e636d6d19565e8e9f0ff83e246f541babdd3ec3ec9cf5b4e148985dc7e13f12f1accd01ff14f9185c84a5d62422e62ca32cebe18c413508f2409402b2d1fa3fbeebfe37dd5a785f6167bfdd8ad2fef4110ecf1e30955050170bd2a1274 }

condition:
	$a0
}

        
