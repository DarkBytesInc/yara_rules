rule Win_Spyware_Banker_1121
{
strings:
	$a0 = { a39bee0da665d184484064564f4db456c178aa719ca38234272112671effff9c144acaa413fb6b6743f8ac77bf4a9e4c71341b17ca7276e3d36f63c8f077b4bc25fe3943c16e0efa142a377710b8a63c1e0d31e757bdfaaae37430e6f3dc78bed88ec47a6dae704a0228336daf817b418e32acb02a5bbf5d122db11b3586ee7f7f09039e }

condition:
	$a0
}

        