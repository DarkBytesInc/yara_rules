rule Win_Trojan_SdBot_4428
{
strings:
	$a0 = { a5746f051412ae21ba83814ad0881825375cb30e40411c2ae23fac528ce1200510a483e02409571e129d970a10288e0f9694fd0c2c82708f80c230c8818790340f25802e0020389571797f29e83c0704ab89724bf784770580886af2a91f53fa583d7d33411896639bf1e956f9f4210930102c925c8af3fa9563fbe60e4ef7d0b9560aec0018f9c345f8626f143213aa }

condition:
	$a0
}

        