rule Win_Downloader_Agent_31608
{
strings:
	$a0 = { 9641560548c3fb8f215c9701304e2c25764a297531549e68f050474eb35df08148c32b5372593d352c2d8a28ed29530eae24e4136f20e143283e565ee93a8f78aa37388148c32b656b3385d8240b32c5e50febe3a6025cfe670659ae2018eeb3e11c3795a211808148c32b886315ad581ef91a45dffdc3639cf0747e5df4712e1aeac633dbee1f1598e3a88148c32b0859e715b516df }

condition:
	$a0
}

        