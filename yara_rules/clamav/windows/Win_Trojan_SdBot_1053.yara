rule Win_Trojan_SdBot_1053
{
strings:
	$a0 = { af300fad546eea72642078219ecc883d7b95872a8cf29a33950d28595f8ae79bfb32ee8a1028ecdaa5ea7d5500d5fb443efb21b63415bd4284ecf7488baca626d404a497530ae88172ec74bf08b7020be9a5bfa5b30eae0641e194b998f6e4349c82f776c06b45d3de938a90ced819556a5e9f41082c6f65c95e7a32173566f8e39ab9f549b152aa48438420e13deff3f1eb73296333 }

condition:
	$a0
}

        