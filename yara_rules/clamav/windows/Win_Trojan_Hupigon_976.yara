rule Win_Trojan_Hupigon_976
{
strings:
	$a0 = { 7177983bd5629ccc39c08caa6feebd8a3cc7e52a994bd72c35d6fc494e18943994e08c2bcd7dcd183752ab3c82fa8968fd6a99e0be347e26736102afe6f2fa85db6fe20bb6a369b2929c1b0253224d036b5589c913115889b454baab7eb97fdc4a3f }

condition:
	$a0
}

        
