rule Win_Trojan_Dvl_2
{
strings:
	$a0 = { 646f7768696c6564766c3d64766c646f63756d656e742e77726974652264766c2339226c6f6f70 }

condition:
	$a0
}

        
