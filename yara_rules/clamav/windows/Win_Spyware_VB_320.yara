rule Win_Spyware_VB_320
{
strings:
	$a0 = { de9a26070c34dad7c6c8eae0019ba669f2fcf4f10e98072637eed64dd3344dda2a283c3828e961d33452468a6a9303e681747e8121e962787df7729b4d93031660704250f961d3342406763e4daed83420d430164dd3e48cc4aca4650ed8e4859a9c69eac14c940924eac6119b5cb02af4445c3007cc06e033776672c2 }

condition:
	$a0
}

        