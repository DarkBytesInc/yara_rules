rule Win_Worm_Sytro_3
{
strings:
	$a0 = { 732046756c6c20446f776e6c6f616465722e65786500000000558bec33c95151515153bb2c0c450033c05568efdd440064ff306489208d45fce85bfaffff8d45fcba04de4400e8fa68fbff8b45fce85aaafbffc703010000006a008d45f4e836faffffff75f46814de44008b03ff3485c4fb44008d45f8ba0300 }

condition:
	$a0
}

        