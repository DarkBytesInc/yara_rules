rule Win_Downloader_1271_1
{
strings:
	$a0 = { 46ddb403d597fdc72669ba1db8d732faed9afc6a408579abc276afacc38bac8a5bb6700903e45c987edcf9f136ad27ca04424b0e44051ce25713aef77485d7a4898389f311b9ee00695e5785ea9f3d4097dcb1ffb3177910a691 }

condition:
	$a0
}

        
