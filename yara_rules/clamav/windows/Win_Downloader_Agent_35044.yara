rule Win_Downloader_Agent_35044
{
strings:
	$a0 = { b262fa8a119bbb8c1bf108c5bb99bbda5ccbdef431f588a762d8dcd460a306f734f1dbf565c26cb605f5886712acd6c86ac2d4e331f58cba6faad0e331f58cbe73b6cce331f58ca277b2c8e331f58ca67bbec4e331f58caa7fbac0e331f5 }

condition:
	$a0
}

        
