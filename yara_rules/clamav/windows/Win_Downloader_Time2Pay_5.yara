rule Win_Downloader_Time2Pay_5
{
strings:
	$a0 = { f21ae3ff06a74c65d3f87d75f6cd6d69e5f47365f6f849b06e62e08be3b917571a639cc96eaedf33416fb1f740d46b15ef992da782eae07ffbdf0d3b40eff45fcd5e4a8b7b1cf3c094d3498dd42ec3b66e5548334acd965d6b5b16c19254d2cafb0bd4655a54d3935c15d1cf420ac4662a4da323404fce2b4251cb }

condition:
	$a0
}

        
