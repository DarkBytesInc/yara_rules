rule Win_Downloader_Agent_32186
{
strings:
	$a0 = { 00e56804206e19c199f978b534db66f76e550cc174114e7ec442ec0a37d4fe1bb1900420e97634db588c457cab27b4caddba66f89df905a35aa9bc78582cbf59ea39337a5d6cb57e80e53e5ea2a183e0aae969552258c68a795b643eb7b3dd81e2662b5c9e57fef60f670f072af1ae561759b29cb4743e32e696d4554f41046151b415cd95e899f805c78f8a11316184892783f8 }

condition:
	$a0
}

        