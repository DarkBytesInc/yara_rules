rule Win_Trojan_SdBot_3539
{
strings:
	$a0 = { db212cb820727824110ecb4bce6397b186856464e144c64b0dc07dc2a9d53838b22e62a56606d29ca90a3c3c88ebb7bd272003fc87aec6684b98e576db5f1582bed8fb1d96a82a8c40243f5a7068ff8d69fda5db0c650c45e96d50b93fa828ac561e8f6122f493a49c7f8b05a0c0f4ea0826f62544c468deeb25354eb15dfc34cc80a9badeccde2cb04a855e4ae0151f81d0fefd4580 }

condition:
	$a0
}

        