rule Win_Trojan_Agent_33989
{
strings:
	$a0 = { 94458b8929e626dcf74b786e64bfc6eeb0e7dba9f1af221b18895f9e0449fcdb2dd540c7e07ca2ad3f34f2466667f32188127ab210d889ec3b6f3c080c9cb9c7917d23a2019454c2632d1dfe75dc8af70d855d0697fbf0750436a39a1bde41dbd88cbf48e09c58917a762bc7f3a29d415f491ec5b4416e8bce70b58af69626fb14ff242a1641c6b8ee213960 }

condition:
	$a0
}

        