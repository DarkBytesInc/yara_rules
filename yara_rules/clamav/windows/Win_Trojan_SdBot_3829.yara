rule Win_Trojan_SdBot_3829
{
strings:
	$a0 = { 4b4f696b9e6a57f2da7e3b9e2667908e8a673d7e6ac9cb8aae9e501d5c7fa5c92ff79709edf97ee2d4bbf95ab37214971d38c00853bb489947dd8f548c3d797bfb2be38626b1aae38114d019d0e81fd6f75dd85d45f7aeb0f14f8eded499ad714da5 }

condition:
	$a0
}

        
