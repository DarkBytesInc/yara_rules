rule Win_Trojan_SdBot_3712
{
strings:
	$a0 = { 0d9b76129f01fc234da060be52e542decd173178f62bd9fb8cab9a015d074db41a2ca6caa4bae0fac15690fb18a2f0151ae819d0987a239128ff14384ff7a612210149d99eef0dad478802cac73fae812a4862776cb321cd6a14dfe1fdfebe78d9b4bd90c611e1ce4c62f848c28d }

condition:
	$a0
}

        
