rule Win_Trojan_SdBot_3895
{
strings:
	$a0 = { 47c0dd8f77c8eb456f56ff1bef09e9ecb17ac6b4436a479f9cb3a676088a13556b964db6050594fd41ed77e947018fbf5def15acf6f58e1670c98b92eece51ffe5ca1e46f9f163ae8c1a31a16b845d143da10439ec585a961b14cf1a }

condition:
	$a0
}

        
