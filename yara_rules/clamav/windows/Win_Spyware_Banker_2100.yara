rule Win_Spyware_Banker_2100
{
strings:
	$a0 = { 71a82bc4cadf972d4f11b69f0ed45b89f1aa68630777c1a75ca48153f497f5e5f471b2fd532f090a42f6b170471c4fae3b0b566efbf17c8c08824627f866ef22810daed5c9d32c10b4513a803ea149af345af144a6b92f5351744af4b1477d0f1cd8785e7789ec24e40b5c468c9998f331e6 }

condition:
	$a0
}

        