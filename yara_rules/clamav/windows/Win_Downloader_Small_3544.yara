rule Win_Downloader_Small_3544
{
strings:
	$a0 = { bbb9b939a1c2bdb9b944f619c9b9ba3c7dcd464dddcdbab9b90b6cba0f4157e1c3b9b9b89021bdbab9b946fdddcd09219dccb9ba21ddcdb9ba21bbb9b939a188bcb9b94605dddd0aa1feb8b8b844e615c9b9ba3c7dd13d79c83da0b9b9b943 }

condition:
	$a0
}

        
