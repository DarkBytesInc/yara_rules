rule Win_Trojan_VBS_42
{
strings:
	$a0 = { 77726974656c696e6520224063645c22 }
	$a1 = { 696e666563742e77726974656c696e65202240617474726962202d73202d68202d72202a2e31737422 }

condition:
	$a0 and $a1
}

        