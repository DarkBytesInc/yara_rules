rule Win_Trojan_Pakes_927
{
strings:
	$a0 = { c0ba1b5cff5bd1f9ea2ac4703565ea4edddc663e87c5cf1a1c2f8f533dd54e6ec49e8985fbd43da879e46a5348659b5c96e8ffed28d5d22b7abedd13c9222b180b2ca4ecdb1bc7071c184b84c68d991123a30e5abe9c9dfb2f06d43b0d9b39a82b97381efcf4186a1e8805f16e36b1c662b605ecbdbaaac7e3851d }

condition:
	$a0
}

        
