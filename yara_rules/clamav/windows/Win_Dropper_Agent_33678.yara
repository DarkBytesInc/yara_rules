rule Win_Dropper_Agent_33678
{
strings:
	$a0 = { d9e9a509e6ee306549aa37e14948d1829abcddd35197dca1b2e6e8349433105c4ec1b43f0c5c8af8f125278f845ae4733f74ed69411f81f663ee59b573a503f2bf8fff3c87a90f34fa1ab847c72fc79b4732ea73f5d3c309b3657bc64770ca23444fc8b5b1f969b64d13221b3d125eaae374443aa53aa5683947abb0f85661b877eae74c41460d897b84d4ba503382e3 }

condition:
	$a0
}

        