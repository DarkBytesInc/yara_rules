rule Win_Downloader_Small_3540
{
strings:
	$a0 = { 351de1cdce35c1e0cdce35cfcdcd4db5d6d1cdcd580a2dddcdce5091e15a61f1e1cecdcd1f80ce23556bf5d7cdcdcca435d1cecdcd5a11f1e11d35b1e0cdce35f1e1cdce35cfcdcd4db59cd0cdcd5a19f1f11eb512cccccc58fa29ddcdce50 }

condition:
	$a0
}

        
