rule Win_Downloader_Zlob_1888
{
strings:
	$a0 = { 83ec348b1d502e4000ff93510100008983a7020000c783fc0600002800000080ca4e80ea7183ec0c8b83a702000089042480f6ec80e19fc744240428000000b1c980cd8a2c9a8bbb0f060000897c240880c6faff93320100008983010a000080c23d83bb010a0000007402eb05e9e3010000c683f40a00007580eebdc683fb0a00006c80cac2c683fd0a00006780e1fd80e22ac683fa }

condition:
	$a0
}

        