rule Win_Downloader_Coreshell_2
{
strings:
	$a0 = { 8b45??8b08c1e1038b55??030a8b328b7d??8b1f0fb6343301f1c1e1048b3281c60100000081e6070000008b1f0fb6343331f18b3281c60200000081e6070000008b1f0fb634338b18c1e303031a8b02050300000025070000008b170fb6040231c321de0fafce88c88b4d??88010fb6118b75??8b1ec1e3038b45??03188b45??8b000fb60c1831d1880c188b45??8b0881c1010000008908 }

condition:
	$a0
}

        