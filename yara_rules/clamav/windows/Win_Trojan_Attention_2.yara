rule Win_Trojan_Attention_2
{
strings:
	$a0 = { 1f0e0706c6068801909090b435b003cd218c061701891e150107c6069e01909090b425b003ba3201cd21c606ae0190 }

condition:
	$a0
}

        
