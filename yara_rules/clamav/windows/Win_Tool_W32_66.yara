rule Win_Tool_W32_66
{
strings:
	$a0 = { 656d7074696e6720746f2063726173683a2025730a00000000556e61626c6520746f2063726561746520736f636b65745b25645d2e0a00000055736167653a202573203c7461726765743e0a0028632931393937205468652050696e6b205468696e6b65722c20416c6c205269 }

condition:
	$a0
}

        