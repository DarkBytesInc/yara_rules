rule Win_Downloader_JS_248
{
strings:
	$a0 = { 7b6e3030352b3d28693439656265633561336263343328633236313134303634346934396562656335613339353333286e3030342e7375627374722869343965626563356133623038392c32292929293b7d }

condition:
	$a0
}

        