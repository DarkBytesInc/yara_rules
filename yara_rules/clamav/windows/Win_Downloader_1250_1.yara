rule Win_Downloader_1250_1
{
strings:
	$a0 = { 63b1ecc685b3fbffff3580f600c6859dfbffff4c80ca1580e5a7c685a9fbffff38c6859cfbffff43c685bdfbffff33b5bb80c124c685b8fbffff3680f24b80f582c685cdfbffff6f80e901b6fdc685b0fbffff2dc685c1fbffff4680c16580f585c685c7fbffff7d80e561c685c4 }

condition:
	$a0
}

        
