rule Win_Trojan_Hupigon_1464
{
strings:
	$a0 = { 58f2014973623a2eefb1d264c9e02af0513ef85935fad7cb6a964f84eaa750de26536b35145d9dcbc615e588ad03aa899de431dff80a211b89f98f7d808890e9d6d192baa7d64717d0aeaad0a5bb36a47d4e96fd9076e02ed04ad8c573c1a48f453808c2dad89a661b9c3d7ad5bb5466cfcaf1ac46681f8bf4ef981b70b1449b4c3b016da152db9c16c92ea6 }

condition:
	$a0
}

        