rule Win_Trojan_Mybot_4540
{
strings:
	$a0 = { 37402e23027f843643672a30788797bf597575457a040c07fc5a2575b4e6b83785cd4ac7fa2cc66f41e8af566d5da5423cb0543ebc262f43f6b013b75f5f153ddf3f5792035dc8205b38beef213fdc59b8852c5eff956c7973a94c0f011156311e29e0c60d5acbf4c21bc7a82f21aa0a483948c1f11a4d3b78661fe69b493004c96782f71eaac04191bf298a47678b0f7cbca2959f1d }

condition:
	$a0
}

        