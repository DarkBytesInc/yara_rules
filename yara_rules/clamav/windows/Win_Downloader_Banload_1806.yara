rule Win_Downloader_Banload_1806
{
strings:
	$a0 = { 909f57c21cef3a77ceda0f4d4976c8d6b1235df6a754c5d8a4ac92315cfe6aa34dbacfe06b73da045338a01daab6f5d4b747c20cc50d51f9f8a30acb8e2b1401f7c4d153b3b194206d2f4cd2fcde754a131e6b56a968ed1d9936fd83420db9f2aa06c1a4 }

condition:
	$a0
}

        
