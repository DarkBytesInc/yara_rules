rule Win_Trojan_Hupigon_1575
{
strings:
	$a0 = { 1d8570c4a6987f1202289574d48f8f76ff874de0a16e830e2801c88419abe76114c455cee3d03dc646fe74fbd326cc071d69ca0a3838d5c09b54e2ab5a57e2580ef4170d8875bc298a7f9f356f9c9d0c93f690edf35f9aef656cdb698f41f398f2292a279ef5231db5c9502b8cd622f37602033a4667bbcdd5e198 }

condition:
	$a0
}

        