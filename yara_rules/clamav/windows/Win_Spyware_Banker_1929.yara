rule Win_Spyware_Banker_1929
{
strings:
	$a0 = { 542b0c90b02fc082d83287c72181e013c965b9104c338db4696d99f8154cf3c63d39a147921fa4c932e179503f188aea82120907a75c53e920d5f6841211064f43090df2ad3d3e5dddd7a0174e187e5157219453c60de957b9719d8824c0bbae0beaf915704e209e414082887029806376978c23a0494f15ae3f00315dc9c796b3746b329f4f7e0b10464543c8a5a7cc54ba8b36f7 }

condition:
	$a0
}

        