rule Win_Trojan_Mybot_8424
{
strings:
	$a0 = { a3b73faa7b1898e297b080ba33a251671e5353aa9593234b5a72b2086250b0ed80f2186e1e282061305601a6743f2ff7b0dd59a813c1e5ffdedb2d2d1efc7bc1766050e0da769e545ccce478df2e98c0a1a3aca84b }

condition:
	$a0
}

        
