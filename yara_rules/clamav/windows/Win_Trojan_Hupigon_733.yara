rule Win_Trojan_Hupigon_733
{
strings:
	$a0 = { 9d552b940c4cdfc36a2b1ecda08358fb4f2954765c5e90e7e4aa20959b8951423accf04a80ddd3ce0603a8f527b21bc88a281ff5cf839fc509cf506d9ccbeee4955e2134f5e11a6ec2bb502b052f95504f503cb8099db424 }

condition:
	$a0
}

        
