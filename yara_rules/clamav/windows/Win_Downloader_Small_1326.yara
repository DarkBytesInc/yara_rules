rule Win_Downloader_Small_1326
{
strings:
	$a0 = { 5c6d7331f6a4e54774c2686faccf1070286179607c2edad228320d19247322147e283332428a343811687420 }

condition:
	$a0
}

        
