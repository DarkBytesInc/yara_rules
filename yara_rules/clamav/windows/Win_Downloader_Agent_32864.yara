rule Win_Downloader_Agent_32864
{
strings:
	$a0 = { 69ec384f8971138494c4984f4071e85654e99f0ded13c222538fee05a2bb51304933361fa85b600d81c6f9649ebb1ec7283bd69dcaa8fdcf46c21556365f }

condition:
	$a0
}

        
