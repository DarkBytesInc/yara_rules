rule Win_Spyware_Banker_3794
{
strings:
	$a0 = { 230052418a8a0a323f05620210089ce72438c1bb6b4d6e6e637737b9afe1dfc077b99dc816f77206db9de036ee40d6af22dd582f6b790569011ae482d720b75ce41b5c836f5c90adb9c12b72416b901bd7380d7b906f77720bbddc836eee02dddcdbb9dceffffffb7dfef5ebdfbf9cf3cf7e7cf7e79e739cfdbd7dfd0450b8c1e4186d76bb4d9ecb6a1a33e6 }

condition:
	$a0
}

        