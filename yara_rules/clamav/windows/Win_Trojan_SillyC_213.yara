rule Win_Trojan_SillyC_213
{
strings:
	$a0 = { 5d81ed06019090908db6ec01909090bf0001905790a590a49090b41a908d9605039090cd21b824359090cd2190 }

condition:
	$a0
}

        
