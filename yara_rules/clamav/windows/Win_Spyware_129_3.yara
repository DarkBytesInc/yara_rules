rule Win_Spyware_129_3
{
strings:
	$a0 = { c1b035d9cd364abbb721865d99cbe135da71d140820e7a3f6bfadac2a2c851d34612e769e38e3e5397476174a9fdcd2a58ca7c0b6c88eaca676e86467b4234d108817f0df0b06a29c4635f4d2a5e27e9cbe883bf7d5ff37a54f9bfffba939ba9c6b752ffbfe5e738bf667f4c }

condition:
	$a0
}

        
