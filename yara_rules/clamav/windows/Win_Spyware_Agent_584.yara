rule Win_Spyware_Agent_584
{
strings:
	$a0 = { 6074e724bb86cc35549749f0ee109294f4ad5261764d6f7836a1c4740b436c7200cceccd2f0cff85f8cbbbf0c7bdb8f6c8cbc873a150e316ea706c0e37f60cf2cb9e0f23c6f3d2b546f79b132eac6d31bf06cac9befacce517ba6fdc62664cd06b443f6e4d61693d5af8 }

condition:
	$a0
}

        
