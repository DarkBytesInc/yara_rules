rule Win_Downloader_Keenval_3
{
strings:
	$a0 = { 35591f37a3ea4e6d1fc114eb5e59bfb90e424ea959cd153318120a0bfdf497744d3632ecfd6c8d7e9c5e95cafc7176d5cb67ef1aaf0c5665cd55779457c93f7334a1b97ebe9be4c3a680963deafb2b8f1e6dbc82e7cb5dbdfb839866bcc6210d33eb6be573a3579ccb66148ce585b7459fb2315e53b8 }

condition:
	$a0
}

        
