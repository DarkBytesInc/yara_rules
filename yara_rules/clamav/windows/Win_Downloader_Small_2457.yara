rule Win_Downloader_Small_2457
{
strings:
	$a0 = { 7a2e1e25b4bc1b21ad2752ea57269efd12db15a19ece26126a88d05d5c926511ada4faec0270b78e3771abde604cbd952645bd99397d356e434abd8c220dddac3e6ec9f7ad6127f2116db580336cbaa13b6cbdac4251aa8c2076ad9d1b6c2c98adcbbc821f6dba983e }

condition:
	$a0
}

        
