rule Win_Trojan_Bancos_1154
{
strings:
	$a0 = { c5abcb717f16dc296ce4f7e3a8e122079fa5a91b79919515b3984b4e8dbfc9ad8db05ffed2a9a19a8d33327040e884c26e1afbc7df7f1c5785597fb7a9f7b85c87a8ca95aa7d5bdcb4eccb1fd0cc85f54d4aeb9b4a }

condition:
	$a0
}

        
