rule Win_Trojan_SdBot_1856
{
strings:
	$a0 = { 1fa666f9f50a7b9277452a93f290cc65a5d28c41bc803c4459c70c35941c813ed516fd70d90c7ea5dcd0a4bfee939f32ae2f952eaba2e0c92c83cceb24e8c8558d701142bfc98abe9f12cfbeb3c3a7b1b23815b6b6a818950ed560cac179d5d94371544b }

condition:
	$a0
}

        
