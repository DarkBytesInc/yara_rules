rule Win_Trojan_Bancos_890
{
strings:
	$a0 = { 701c7262e05e92c48939e0e857b3dd966888aa343731d6113060ac7d6437f452da0b067051bb344b8cf0f363825efcbc1eafe4a761436e72b35925620798abbeb1ef1f8f6162876cbebab54336737db6efa93ce1635261602353674c3fd86646e77b21137700c78fe0fac5eba21a65960e77aa146ac4a9706b3e8f7f5aa7202f }

condition:
	$a0
}

        