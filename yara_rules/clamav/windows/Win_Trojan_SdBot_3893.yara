rule Win_Trojan_SdBot_3893
{
strings:
	$a0 = { f9bd52857cd8bbef3144179133f80767bbfb43dbeb87c1f1a89e858853024ea326ca4c661c7871f36ea9c6607da5111cb9cbb639e0679a67ce2b2e98705cb6e6aa2eb6762b4e8de8d0227dd09fed6af94a61c80ed9a79d1e5450c1de }

condition:
	$a0
}

        
