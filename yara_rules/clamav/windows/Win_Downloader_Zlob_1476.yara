rule Win_Downloader_Zlob_1476
{
strings:
	$a0 = { 583d03db00e871eef55a4f50abbd3dc3155c1eb365dec5d82882b8cd752a941b168f5db3bff115c68ee9c5943f376322e9498b4069c44f0759a413ddece1ac3e146c24fcb90d5186b52572ead8c3731fdf5943ea5670 }

condition:
	$a0
}

        
