rule Win_Trojan_Pakes_971
{
strings:
	$a0 = { 23c1ea3ab9d9c69f5b4dd289c335b2e0f46edf716cc2b44b6663e9bbac0b69e480810f6b0632d87df643921843c2fa3d94727a57b4bc9e8ed7329e37073bed99b9735b3db95bde4c38ea7ed1f7b1c06bde6d4a8dec08d712b0905e024721830ddf971e6e88d582b68ef36ef9ddf59437ef3b88edeed09e87842a523cc8 }

condition:
	$a0
}

        